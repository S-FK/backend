#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import division, unicode_literals, print_function

from pathlib import Path

import spacy
from spacy.util import minibatch, compounding
import json
import sys

import textacy
import textacy.keyterms
from collections import defaultdict

import random
import os
from flask import Flask, render_template, jsonify, redirect, url_for, request

import json
import itertools

app = Flask(__name__)

@app.route('/getresults/', methods=['GET'])
def sendbackresults():
	return "haha"

def main():
	mess = []
	try:
		with open("messagelist.json", 'r') as f1:
			datastore = json.load(f1)
			for item in datastore:
				mess.append(item["results"])

		clustering_results = derdesdemden(input=mess)

		result1 = clustering_results.split(",")
		final_json = [{"keywords":result1}]

		return jsonify(final_json)
	except Exception as e:
		print(e)
		return("Nope, nothing to see here!")

def derdesdemden(input=None, output_dir="newout_updated", algorithm="s", n_key_float=0.75, n_grams="1,2,3,4",
		cutoff=10, threshold=0.5):
	if algorithm != "t" and algorithm != "s":
		return("Specify an algorithm! (t)extrank or (s)grank")

	if input is None:
		return("Specify input file with -i")

	alldata = []

	for curline in input:
		alldata.append(curline)

	# Preprocess data by removing garbage keywords
	alldata = clean_data(alldata)

	# the cummulative tally of common keywords
	word_keyterm_cummula = defaultdict(lambda: 0)
	# the mapping of journals to the common keywords
	word_keyterm_journals = defaultdict(lambda: [])

	en = textacy.load_spacy_lang("en_core_web_sm", disable=("parser",))
	for item in alldata:
		msgid = item.split(' ')[0]
		curline = item.replace(msgid, '').strip()
		curdoc = textacy.make_spacy_doc(curline.lower(), lang=en)
		curdoc_ranks = []
		if algorithm == "t":
			if n_key_float > 0.0 and n_key_float < 1.0:
				curdoc_ranks = textacy.keyterms.textrank(curdoc,
					normalize="lemma", n_keyterms=n_key_float)
			else:
				curdoc_ranks = textacy.keyterms.textrank(curdoc,
					normalize="lemma", n_keyterms=n_key)
		elif algorithm == "s":
			ngram_str = set(n_grams.split(','))
			ngram = []
			for gram in ngram_str:
				ngram.append(int(gram))
			curdoc_ranks = textacy.keyterms.sgrank(curdoc,
				window_width=1500, ngrams=ngram, normalize="lower",
				n_keyterms=n_key_float)

		for word in curdoc_ranks:
			word_keyterm_cummula[word[0]] += 1
			word_keyterm_journals[word[0]].append((msgid, word[1]))
			if len(word_keyterm_journals[word[0]]) > 10:
				newlist = []
				min_tuple = word_keyterm_journals[word[0]][0]
				for tuple in word_keyterm_journals[word[0]]:
					if tuple[1] < min_tuple[1]:
						min_tuple = tuple
				for tuple in word_keyterm_journals[word[0]]:
					if tuple[0] != min_tuple[0]:
						newlist.append(tuple)
				word_keyterm_journals[word[0]] = newlist

	word_keyterm_cummula_sorted = sorted(word_keyterm_cummula.items(),
		key=lambda val: val[1], reverse=True)

	quint = 0
	quint_printout = ""
	for entry in word_keyterm_cummula_sorted[:cutoff]:
		quint_printout += entry[0] + ","
		quint += 1
	quint_printout = quint_printout[:-1]
	print(quint_printout)
	return quint_printout


"""
	Preprocessing function that removes excessive punctuations, any floating
	punctuations, any file extensions, and unneccessary entities.
"""

def clean_data(journal_list):
	nlp = spacy.load('en_core_web_sm')  # make sure to use larger model!

	fine_data = []
	# Delete any occurrences of these but keep the words attached to them.
	garbage_punc = ['...', '....', '.....', '///', '////', '/////', '---',
		'----', '-----']
	# Remove any files with these extensions
	file_exts = [".html", "[/url", ".xxx", ".jpg", ".jpeg", ".png", ".gif",
		".txt", ".doc", ".docx", ".pdf"]
	# Look for any words which contain these X's as substrings, remove them.
	xs = ['xxx', 'xxxx', 'xxxxx']
	# Delete any occurrences of these if they occur as a single token
	punctuations = ['!', '?', '_', '/', '-', '+', '=', '>', '|', '[', ']',
		'{', '}', '(', ')', ',', '#', "\"", "\'"]

	for curline in journal_list:
		# Separate the journal ID from the message, then remove all non-ascii
		# characters
		msgid = curline.split(' ')[0]
		curline = curline.replace(msgid, '').strip()
		curline = remove_non_ascii(curline).strip()

		# Get rid of gibberish - remove any excessive punctuations.
		for garb in garbage_punc:
			curline = curline.replace(garb, '')

		# Tokenize the sentence to further prune the sentences.
		doc = nlp(curline)
		strtok = ""
		for token in doc:
			if token.ent_type_ not in remove_these_entities:
				strtok += token.text + " "

		# Remove all punctuation marks.
		for char in strtok:
			if char in punctuations:
				if strtok[0:2] == char + ' ':
					strtok = strtok[2:]
				elif strtok[-2:] == ' ' + char:
					strtok = strtok[:-2]
				else:
					strtok = strtok.replace(' ' + char + ' ', ' ')

		stringtoanalyze = strtok.strip()
		removal_dump = []

		"""
			Go through the string and prune the following:

			1. Any non-English words.
			2. Any word greater than 20 characters in length.
			3. Any Base64 encryptions and file names.
			4. Any words with lots of 'x' in it.
		"""
		for word in stringtoanalyze.split():
			if not isEnglish(word):
				removal_dump.append(word)
				continue
			if len(word) > 20:
				removal_dump.append(word)
				continue
			if word[-4:] in file_exts or word[-5:] in file_exts or \
					word[-2:] == "==":
				removal_dump.append(word)
				continue
			wordlw = word.lower()
			if "xxxx" in wordlw or "xxx" in wordlw or wordlw[:4] == "xxxx" or \
					wordlw[-4:] == "xxxx" or wordlw[:3] == "xxx" or \
					wordlw[-3:] == "xxx":
				removal_dump.append(word)
				continue
			for exes in xs:
				if exes in wordlw:
					removal_dump.append(word)

		for rem in removal_dump:
			if stringtoanalyze == rem:
				stringtoanalyze = ""
			elif stringtoanalyze[:len(rem)] == rem:
				stringtoanalyze = stringtoanalyze[len(rem):]
			elif stringtoanalyze[(-1 * len(rem)):] == rem:
				stringtoanalyze = stringtoanalyze[:(-1 * len(rem))]
			else:
				stringtoanalyze = stringtoanalyze.replace(' ' + rem + ' ', ' ')

		# If all the pruning results in a nonempty string of length greater
		# than 1, it is safe to use for clustering.
		stringtoanalyze = stringtoanalyze.strip()
		if len(nlp(stringtoanalyze)) > 1:
			fine_data.append(msgid + ' ' + stringtoanalyze + '\n')

	print("Done with cleaning data.")

	return fine_data


"""
	Functions to remove any non-English words and emojis from journals for
	preprocessing purposes.
"""
def remove_non_ascii(s):
	for char in s:
		if len(char.encode('utf-8')) > 3:
			s = s.replace(char, '')
	return s


def isEnglish(s):
	try:
		s.encode(encoding='utf-8').decode('ascii')
	except UnicodeDecodeError:
		return False
	else:
		return True

if __name__ == '__main__':
	#app.run(debug=True, host='0.0.0.0',port='8000')
	main()
