import re

from lib.elements import DropdownWithHelp, VectorInput


def get_version() -> str:
    try:
        with open('VERSION', 'r') as version_file:
            return version_file.read().strip()
    except FileNotFoundError:
        return ""

def parse_vector(vector: str) -> dict:
    try:
        vector = vector.strip()

        # regex form check
        if re.match(r"^CVSS:3\.1/(AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NHL]/I:[NHL]/A:[NHL])$", vector) is None:
            raise ValueError("Invalid vector. Please check your input.")

        parts = vector.replace("CVSS:3.1/", "").split("/")
        values = {part.split(":")[0]: part.split(":")[1] for part in parts}

        return values

    except Exception as e:
        raise ValueError(f"⚠️ Error: {str(e)}")


