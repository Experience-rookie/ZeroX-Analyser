#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import re

def nth_replace(string, old, new, n):
    """
    Replaces the nth occurrence of a substring in a string.

    Parameters:
    - string: The original string.
    - old: The substring to replace.
    - new: The replacement substring.
    - n: The occurrence number to replace.

    Returns:
    - Modified string with the nth occurrence replaced, or original string if occurrences are less than n.
    """
    if string.count(old) >= n:
        left_part = old
        right_part = old
        parts = string.split(old)
        modified_parts = [left_part.join(parts[:n]), right_part.join(parts[n:])]
        return new.join(modified_parts)
    return string.replace(old, new)


def display(path, payload, vulnerability, line, declaration_text, declaration_line, highlighted, occurrence, plain):
    """
    Displays details of a detected vulnerability.

    Parameters:
    - path: File path where the vulnerability was detected.
    - payload: Information about the detected payload.
    - vulnerability: The vulnerable code snippet.
    - line: Line number where the issue was found.
    - declaration_text: Variable declaration information.
    - declaration_line: Line number of the variable declaration.
    - highlighted: Highlighted text for display.
    - occurrence: The occurrence number of the vulnerability.
    - plain: Boolean indicating plain text output.
    """
    header = "{}Potential vulnerability found : {}{}{}".format(
        '' if plain else '\033[1m', '' if plain else '\033[92m', payload[1], '' if plain else '\033[0m'
    )

    line_info = "-->{}{}{} in {}".format(
        '' if plain else '\033[92m', line, '' if plain else '\033[0m', path
    )

    vuln_snippet = nth_replace("".join(vulnerability), highlighted, 
                               "{}".format('' if plain else '\033[92m') + highlighted + "{}".format('' if plain else '\033[0m'), 
                               occurrence)
    vuln_snippet = "{}({})".format(payload[0], vuln_snippet)

    rows, columns = 45, 190
    print("-" * (columns - 1))
    print(f"Name        \t{header}")
    print("-" * (columns - 1))
    print(f"{'' if plain else '\033[1m'}Line {'' if plain else '\033[0m'}             {line_info}")
    print(f"{'' if plain else '\033[1m'}Code {'' if plain else '\033[0m'}             {vuln_snippet}")

    if "$_" not in highlighted:
        declaration = "Undeclared in the file"
        if declaration_text:
            declaration = f"Line n°{'' if plain else '\033[0;92m'}{declaration_line}{'' if plain else '\033[0m'} : {declaration_text}"
        print(f"{'' if plain else '\033[1m'}Declaration {'' if plain else '\033[0m'}      {declaration}")
    print("")


def find_line_vuln(payload, vulnerability, content):
    """
    Identifies the line number where the vulnerability exists in the content.

    Parameters:
    - payload: Information about the payload.
    - vulnerability: The vulnerability string.
    - content: Source code content.

    Returns:
    - Line number as a string, or "-1" if not found.
    """
    content_lines = content.split('\n')
    for i, line in enumerate(content_lines):
        if f"{payload[0]}({vulnerability[0]}{vulnerability[1]}{vulnerability[2]})" in line:
            return str(i - 1)
    return "-1"


def find_line_declaration(declaration, content):
    """
    Finds the line number of the variable declaration.

    Parameters:
    - declaration: The variable to search for.
    - content: Source code content.

    Returns:
    - Line number as a string, or "-1" if not found.
    """
    content_lines = content.split('\n')
    for i, line in enumerate(content_lines):
        if declaration in line:
            return str(i)
    return "-1"


def clean_source_and_format(content):
    """
    Cleans and formats source code for analysis.

    Parameters:
    - content: Source code content.

    Returns:
    - Cleaned and formatted source code.
    """
    content = content.replace("    ", " ")  # Replace tabs with spaces.
    content = content.replace("echo ", "echo(").replace(";", ");")  # Normalize echo statements.
    return content


def check_protection(payload, match):
    """
    Checks if the matched content contains any protection mechanisms.

    Parameters:
    - payload: List of protection mechanisms.
    - match: The matched content.

    Returns:
    - True if protection is found, else False.
    """
    return any(protection in "".join(match) for protection in payload)


def check_exception(match):
    """
    Checks if the match is an exception.

    Parameters:
    - match: The matched content.

    Returns:
    - True if it's an exception, else False.
    """
    exceptions = ["_GET", "_REQUEST", "_POST", "_COOKIES", "_FILES"]
    return any(exception in match for exception in exceptions)


def check_declaration(content, vuln, path):
    """
    Checks and analyzes variable declarations for vulnerabilities.

    Parameters:
    - content: Source code content.
    - vuln: Vulnerable variable.
    - path: File path.

    Returns:
    - Tuple containing boolean for false positives, declaration text, and line number of declaration.
    """
    regex_include = re.compile("(include.*?|require.*?)\\([\"\'](.*?)[\"\']\\)")
    includes = regex_include.findall(content)
    for include in includes:
        relative_path = os.path.dirname(path) + "/"
        try:
            include_path = relative_path + include[1]
            with open(include_path, 'r') as file:
                content = file.read() + content
        except Exception:
            return False, "", ""

    vulnerability = vuln[1:].replace(')', '\\)').replace('(', '\\(')
    regex_var_decl = re.compile("\\$" + vulnerability + "([\t ]*)=(?!=)(.*)")
    declarations = regex_var_decl.findall(content)

    if declarations:
        declaration_text = f"${vulnerability}{declarations[0][0]}={declarations[0][1]}"
        declaration_line = find_line_declaration(declaration_text, content)
        regex_const = re.compile(
            f"\\${vulnerability}([\t ]*)=[\t ]*?([\"\'(]*?[a-zA-Z0-9{{}}_\\(\\)@\\.,!: ]*?[\"\')]*?);"
        )
        if regex_const.match(declaration_text):
            return True, "", ""
        return False, declaration_text, declaration_line

    return False, "", ""
