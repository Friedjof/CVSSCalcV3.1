import re
from datetime import datetime

from nicegui import ui

def get_version():
    try:
        with open('VERSION', 'r') as version_file:
            return version_file.read().strip()
    except FileNotFoundError:
        return "BETA"


# Metrics (CVSS v3.1 Base Metrics)
AV = {'Network (N)': (0.85, 'N'), 'Adjacent (A)': (0.62, 'A'), 'Local (L)': (0.55, 'L'), 'Physical (P)': (0.2, 'P')}
AC = {'Low (L)': (0.77, 'L'), 'High (H)': (0.44, 'H')}
PR_U = {'None (N)': (0.85, 'N'), 'Low (L)': (0.62, 'L'), 'High (H)': (0.27, 'H')}
PR_C = {'None (N)': (0.85, 'N'), 'Low (L)': (0.68, 'L'), 'High (H)': (0.5, 'H')}
UI = {'None (N)': (0.85, 'N'), 'Required (R)': (0.62, 'R')}
S = {'Unchanged (U)': (6.42, 'U'), 'Changed (C)': (7.52, 'C')}
CIA = {'None (N)': (0.0, 'N'), 'Low (L)': (0.22, 'L'), 'High (H)': (0.56, 'H')}


@ui.page('/')
def main():
    ui.page_title("CVSS v3.1 Calculator")
    ui.add_css('static/styles.css')

    with ui.column().classes('container'):
        ui.label('💻 CVSS v3.1 Calculator – Base Score').classes('title')

        def parse_vector():
            try:
                vector = vector_input.value.strip()

                # regex form check
                if re.match(r"^CVSS:3\.1/(AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NHL]/I:[NHL]/A:[NHL])$", vector) is None:
                    raise ValueError("Invalid vector. Please check your input.")

                parts = vector.replace("CVSS:3.1/", "").split("/")
                values = {part.split(":")[0]: part.split(":")[1] for part in parts}

                dd_av.value = next(key for key, val in AV.items() if val[1] == values.get("AV"))
                dd_ac.value = next(key for key, val in AC.items() if val[1] == values.get("AC"))
                dd_pr.value = next(key for key, val in PR_U.items() if val[1] == values.get("PR"))
                dd_ui.value = next(key for key, val in UI.items() if val[1] == values.get("UI"))
                dd_s.value = next(key for key, val in S.items() if val[1] == values.get("S"))
                dd_c.value = next(key for key, val in CIA.items() if val[1] == values.get("C"))
                dd_i.value = next(key for key, val in CIA.items() if val[1] == values.get("I"))
                dd_a.value = next(key for key, val in CIA.items() if val[1] == values.get("A"))

            except Exception as e:
                result_score_label.text = f"⚠️ Error: {str(e)}"
                result_score_label.classes('error')

        def calculate_cvss():
            scope_key = dd_s.value
            pr_lookup = PR_U if scope_key == 'Unchanged (U)' else PR_C

            try:
                av = AV[dd_av.value][0]
                ac = AC[dd_ac.value][0]
                pr = pr_lookup[dd_pr.value][0]
                ui_val = UI[dd_ui.value][0]
                s = S[scope_key][0]

                c = CIA[dd_c.value][0]
                i = CIA[dd_i.value][0]
                a = CIA[dd_a.value][0]

                vector = f"CVSS:3.1/AV:{AV[dd_av.value][1]}/AC:{AC[dd_ac.value][1]}/" \
                         f"PR:{pr_lookup[dd_pr.value][1]}/UI:{UI[dd_ui.value][1]}/" \
                         f"S:{S[scope_key][1]}/C:{CIA[dd_c.value][1]}/" \
                         f"I:{CIA[dd_i.value][1]}/A:{CIA[dd_a.value][1]}"

                impact = 1 - ((1 - c) * (1 - i) * (1 - a))
                impact_score = s * impact
                exploitability = 8.22 * av * ac * pr * ui_val

                if impact <= 0:
                    base_score = 0.0
                elif scope_key == 'Unchanged (U)':
                    base_score = min(impact_score + exploitability, 10)
                else:
                    base_score = min(1.08 * (impact_score + exploitability), 10)

                score = round(base_score, 1)
                if score >= 9.0:
                    color = 'red'
                elif score >= 7.0:
                    color = 'orange'
                elif score >= 4.0:
                    color = '#d4a017'
                else:
                    color = 'lightgreen'

                result_score_label.text = f"🎯 CVSS Score: {score}"
                result_score_label.classes(f'score {color}')
                vector_input.value = vector

            except Exception as e:
                if str(e) != "None":
                    result_score_label.text = f"⚠️ Error: {str(e)}"
                    result_score_label.classes('error')

        vector_input = ui.input(label="Enter vector (optional)",
                                on_change=lambda x: (parse_vector(), calculate_cvss())).classes('input')

        result_score_label = ui.label("CVSS Score: -").classes('result')

        with ui.row().classes('nice-card'):
            dd_av = ui.select(list(AV.keys()), label="Attack Vector (AV)",
                              on_change=calculate_cvss).classes('dropdown')
            dd_ac = ui.select(list(AC.keys()), label="Attack Complexity (AC)",
                              on_change=calculate_cvss).classes('dropdown')
            dd_pr = ui.select(list(PR_U.keys()), label="Privileges Required (PR)",
                              on_change=calculate_cvss).classes('dropdown')
            dd_ui = ui.select(list(UI.keys()), label="User Interaction (UI)",
                              on_change=calculate_cvss).classes('dropdown')
            dd_s = ui.select(list(S.keys()), label="Scope (S)",
                             on_change=calculate_cvss).classes('dropdown')

        with ui.row().classes('nice-card'):
            dd_c = ui.select(list(CIA.keys()), label="Confidentiality (C)",
                             on_change=calculate_cvss).classes('dropdown')
            dd_i = ui.select(list(CIA.keys()), label="Integrity (I)",
                             on_change=calculate_cvss).classes('dropdown')
            dd_a = ui.select(list(CIA.keys()), label="Availability (A)",
                             on_change=calculate_cvss).classes('dropdown')

    # Add footer
    with ui.footer().classes('nice-card').style('text-align: center; display: flex; align-items: center;'):
        ui.label(f"© {datetime.now().year}, Friedjof Noweck").style(
            'margin-right: 4px;'
        )
        ui.link(
            'Version on GitHub',
            f'https://github.com/Friedjof/CVSSCalcV3.1/releases/tag/{get_version()}',
        ).style(
            'color: #ffff00; text-decoration: none;'
        )

ui.run(favicon="🧮")
