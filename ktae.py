import requests
import json
import time
import yara

import idaapi
import idautils
import ida_kernwin
import ida_idaapi
import ida_segment
import ida_bytes
import ida_nalt

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
VERIFY_SSL = False

API_URL = "<---- PLACEHOLDER FOR API URL ---->"
API_KEY = "<---- PLACEHOLDER FOR API KEY ---->"

HIGHLIGHT_COLOR = 0x40F040F0

class KTAE:
	def __init__(self, api_url, api_key):

		if (not api_url.endswith("/api")):
			api_url += "/api"

		self.api_url = api_url
		self.api_key = api_key
		
	def health_check(self):
		url = self.api_url + "/healthcheck"
		response = requests.get(url=url, verify=VERIFY_SSL)
		return response.status_code, response.json()
	
	def send_sample(self, data):
		url = self.api_url + "/analysis?resetThreshold=false&unpack=false&amongPreviously=false"

		files = [
			("data", data),
		]
	
		headers = {
			"api-key": self.api_key
		}
	
		response = requests.post(url=url, headers=headers, files=files, verify=VERIFY_SSL)
		return response.status_code, response.json()
	
	def get_report(self, analysis_id):
		url = self.api_url + "/report/%s?format=json" % (analysis_id)
		
		headers = {
			"api-key": self.api_key,
			"Accept": "application/json"
		}
		
		response = requests.get(url=url, headers=headers, verify=VERIFY_SSL)
		return response.status_code, response.json()
	
	def get_matched_data(self, data):
		status_code, response = self.send_sample(data)
	
		if not (status_code == 200 and "analysisId" in response):
			return status_code, response
		
		time.sleep(0.5)
	
		analysis_id = response["analysisId"]
	
		while (True):
			status_code, response = self.get_report(analysis_id)
	
			if (status_code == 202):
				time.sleep(0.5)
				continue

			break
	
		return status_code, response

	def format_top_5(self, result):
		info = "None"
		
		if (len(result["top_5"]) > 0):
		
			info = ""
			for i in range(len(result["top_5"])):
				entry = result["top_5"][i]
				info += "%s - %d%%" % (entry["attribution_entity"], entry["similarity"])
		
				if (i + 1 < len(result["top_5"])):
					info += ", "
	
		return info

class MatchedSamplesView(ida_kernwin.Choose):

	def __init__(self, title, items,
			flags=ida_kernwin.CH_RESTORE | ida_kernwin.CH_MULTI,
			width=None,
			height=None,
			embedded=False):
		
		ida_kernwin.Choose.__init__(
			self,
			title,
			[ 
				["MD5", 28 | ida_kernwin.CHCOL_PLAIN],
				["Size", 6 | ida_kernwin.CHCOL_DEC],
				["Total genotypes", 10 | ida_kernwin.CHCOL_DEC],
				["Matched genotypes", 12 | ida_kernwin.CHCOL_DEC],
				["Total strings", 10 | ida_kernwin.CHCOL_DEC],
				["Matched strings", 10 | ida_kernwin.CHCOL_DEC],
				["Similarity", 8 | ida_kernwin.CHCOL_PLAIN],
				["Attribution entity", 20 | ida_kernwin.CHCOL_PLAIN],
				["Aliases", 70 | ida_kernwin.CHCOL_PLAIN],
			],
			flags = flags,
			width = width,
			height = height,
			embedded = embedded)
		
		self.items = items

		self.Show()

	def OnClose(self):
		self.items = []

	def OnSelectLine(self, n):
		return

	def OnGetSize(self):
		return len(self.items)

	def OnGetLine(self, n):
		return [
			self.items[n].md5, 
			str(self.items[n].size), 
			str(self.items[n].total_genotypes), 
			str(self.items[n].matched_genotypes), 
			str(self.items[n].total_strings), 
			str(self.items[n].matched_strings), 
			self.items[n].similarity, 
			self.items[n].actor, 
			self.items[n].aliases
		]

class MatchedSampleEntry():
	def __init__(self, entry):
		self.md5 = entry["md5"]
		self.size = entry["size"]
		self.total_genotypes = entry["total_genotypes"]
		self.matched_genotypes = entry["matched_genotypes"]
		self.total_strings = entry["total_strings"]
		self.matched_strings = entry["matched_strings"]
		self.similarity = "%d%%" % (entry["similarity"])
		self.actor = entry["attribution_entity"]
		self.aliases = ", ".join(entry["aliases"])

class MatchedSignaturesView(ida_kernwin.Choose):

	def __init__(self, title, items,
			flags=ida_kernwin.CH_RESTORE,
			width=None,
			height=None,
			embedded=False):
		
		ida_kernwin.Choose.__init__(
			self,
			title,
			[ 
				["Address", 18 | ida_kernwin.CHCOL_EA],
				["Genotype / String", 30 | ida_kernwin.CHCOL_PLAIN],
				["Matched", 8 | ida_kernwin.CHCOL_DEC],
				["Used by", 80 | ida_kernwin.CHCOL_PLAIN],
			],
			flags = flags,
			width = width,
			height = height,
			embedded = embedded)
		
		self.items = items

		self.highlight_command = self.AddCommand("Highlight genotypes")
		self.unhighlight_command = self.AddCommand("Un-highlight genotypes")

		self.Show()

	def OnClose(self):
		self.items = []

	def OnSelectLine(self, n):
		item_ea = self.items[n].ea
		ida_kernwin.jumpto(item_ea)

	def OnGetSize(self):
		return len(self.items)

	def OnGetLine(self, n):
		item_ea = self.items[n].ea
		ea_str = "0x%016X" % item_ea if ida_idaapi.__EA64__ else "0x%08X" % item_ea
		return [ea_str, self.items[n].sig, str(self.items[n].matched), self.items[n].actors]

	def OnCommand(self, n, cmd):

		if (cmd in [self.highlight_command, self.unhighlight_command]):

			color = 0xFFFFFFFF
			if (cmd == self.highlight_command):
				color = HIGHLIGHT_COLOR

			for entry in self.items:

				ea = entry.ea
				size = entry.size
				end = ea + size

				while (ea < end):
					ida_nalt.set_item_color(ea, color)

					ea = ida_bytes.next_head(ea, ida_idaapi.BADADDR)
					
					if (ea == ida_idaapi.BADADDR):
						break

		return 0

class MatchedSignatureEntry():
	def __init__(self, ea, size, sig, matched, actors):
		self.ea = ea
		self.size = size
		self.sig = sig
		self.matched = matched
		self.actors = actors

class DataHelper:
	def __init__(self):

		self.data = b''
		self.segments = []
		
		for segment_start in idautils.Segments():

			seg = ida_segment.getseg(segment_start)
			if not seg:
				continue

			segment_size = seg.end_ea - segment_start
			self.segments.append({"address": segment_start, "start": len(self.data), "size": segment_size})
			self.data += ida_bytes.get_bytes(segment_start, segment_size)

	def generate_rule(self, genotypes, strings):
	
		rule =  "rule default {\n"
		rule += "    strings:\n"
		
		for i in range(len(genotypes)):
			rule += "        $g%d = {%s}\n" % (i, genotypes[i]["genotype"])
		
		for i in range(len(strings)):
			rule += "        $s%d = \"%s\"\n" % (i, strings[i]["string"].replace('\\', '\\\\').replace('"', '\\"'))
	
		rule += "    condition:\n"
		rule += "        any of them\n"
		rule += "}\n"
	
		return rule

	def yara_strings(self, strings):

		for s in strings:

			if (type(s) is not tuple):

				# After YARA 4.3.0

				name = s.identifier
				for instance in s.instances:
					offset = instance.offset
					buf = instance.matched_data

					yield (offset, name, buf)

			else:

				# Before YARA 4.3.0

				offset = s[0]
				name = s[1]
				buf = s[2]

				yield (offset, name, buf)

	def scan_data(self, genotypes, strings):

		rule = self.generate_rule(genotypes, strings)
		rules = yara.compile(source=rule)
		
		matches = rules.match(data=self.data)
		
		items = []

		for m in matches:
		
			for s in self.yara_strings(m.strings):

				offset = s[0]
				name = s[1]
				size = len(s[2])
				
				address = None
				for segment in self.segments:
		
					if (offset >= segment["start"] and offset <= segment["start"] + segment["size"]):
						address = segment["address"] + offset - segment["start"]
						break

				if (address == None):
					continue

				index = int(name[2:])

				if (name[1] == 'g'):
					sig = genotypes[index]["genotype"]
					matched = genotypes[index]["matched"]
					used_by = genotypes[index]["used_by"]

				elif (name[1] == 's'):
					sig = strings[index]["string"]
					matched = strings[index]["matched"]
					used_by = strings[index]["used_by"]

				else:
					continue

				actors = ""
				for i in range(len(used_by)):
					entry = used_by[i]
					actors += "%s - %d" % (entry["attribution_entity"], entry["matched"])
				
					if (i + 1 < len(used_by)):
						actors += ", "

				items.append(MatchedSignatureEntry(address, size, sig, matched, actors))

		return items

class KTAE_PLUGIN(ida_idaapi.plugin_t):
	flags = 0
	wanted_name = "Kaspersky Threat Attribution Engine (KTAE)"
	wanted_hotkey = ""
	comment = "KTAE analyzes the \"genetics\" of malware looking for " \
				"code similarity with previously investigated APT samples and linked actors"
	help = ""

	def init(self):
		self.ktae = KTAE(API_URL, API_KEY)
		self.helper = None
		self.health_checked = False
		return ida_idaapi.PLUGIN_KEEP

	def term(self):
		pass

	def run(self, arg):
		self.new_analysis()

	def new_analysis(self):

		if not (self.helper):
			self.helper = DataHelper()

		if not (self.health_checked):
			status_code, response = self.ktae.health_check()

			if (status_code != 200):
				print("Error! Failed to connect to KTAE - %d: %s" % (status_code, response))
				return

			self.health_checked = True

		status_code, response = self.ktae.get_matched_data(self.helper.data)
		
		if not (status_code == 200 and len(response) == 1 and "md5" in response[0]):

			if (status_code == 401):
				ida_kernwin.warning("Please put a valid API_KEY into ktae.py")

			print("Error! Failed to upload sample to KTAE - %d: %s" % (status_code, response))
			return
		
		result = response[0]
		
		if (len(result["top_5"]) == 0):
			print("KTAE: Similarity not found")
			return

		info = self.ktae.format_top_5(result)
		
		items = []
		for entry in result["similar_attribution_entities_samples"]:
			items.append(MatchedSampleEntry(entry))
		
		MatchedSamplesView("KTAE (Samples) - %s" % info, items)
		
		matched_genotypes = list(result["matched_genotypes_with_attribution_entity_samples"])
		matched_strings = list(result["matched_strings_with_attribution_entity_samples"])

		if (len(matched_genotypes) > 0 or len(matched_strings) > 0):

			items = self.helper.scan_data(matched_genotypes, matched_strings)
			MatchedSignaturesView("KTAE (Matches) - %s" % info, items)

def PLUGIN_ENTRY():
	return KTAE_PLUGIN()
