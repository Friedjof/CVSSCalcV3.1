from nicegui import ui
from fastapi import Request

from lib.elements import DropdownWithHelp, VectorInput, Header, Footer
from lib.metrics import metrics


@ui.page('/')
def main(request: Request):
    vector_param = request.query_params.get('vector', None)
    dropdown_objects = []
    ui.page_title("CVSS v3.1 Calculator")
    ui.add_css('static/styles.css')
    ui.add_head_html('''
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.10/dist/katex.min.css">
        <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.10/dist/katex.min.js"></script>
    ''')

    with ui.column().classes('container'):
        header = Header()

        vector_input = VectorInput(
            label='CVSS Vector (Optional)',
            vector=vector_param,
            header=header,
        )

        with ui.row().classes('nice-card dropdown-row'):
            values = vector_input.get_dropdown_value()

            for i, (metric_key, metric) in enumerate(metrics.items()):
                # Create a dropdown for each metric
                dropdown_objects.append(DropdownWithHelp(
                    label=metric['title'],
                    key=metric_key,
                    options=metric['options'],
                    help_text=metric['help_text'],
                    on_change=vector_input.calculate_vector,
                    value=values[metric_key] if values is not None else None
                ))
                dropdown_objects[i].classes('dropdown')

        vector_input.set_dropdown_objects(dropdown_objects)

    # Add footer
    Footer(vector_input)


ui.run(favicon="🧮")
