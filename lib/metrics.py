# Metrics (CVSS v3.1 Base Metrics)
metrics = {
    'AV': {
        'title': 'Attack Vector',
        'options': {
            'Network (N)': (0.85, 'N', 'The attacker can exploit the vulnerability over a network.'),
            'Adjacent (A)': (0.62, 'A', 'The attacker must be in the same network segment.'),
            'Local (L)': (0.55, 'L', 'The attacker needs local access to the target system.'),
            'Physical (P)': (0.2, 'P', 'The attacker needs physical access to the device.')
        },
        'help_text': 'Defines the environment where the vulnerability can be exploited, such as over a network or physically.'
    },
    'AC': {
        'title': 'Attack Complexity',
        'options': {
            'Low (L)': (0.77, 'L', 'The vulnerability is easy to exploit.'),
            'High (H)': (0.44, 'H', 'The vulnerability requires complex conditions to exploit.')
        },
        'help_text': 'Describes the difficulty of exploiting the vulnerability, considering conditions outside the attacker\'s control.'
    },
    'PR': {
        'title': 'Privileges Required',
        'options': {
            'None (N)': (0.85, 'N', 'No privileges are required to exploit the vulnerability.'),
            'Low (L)': (0.62, 'L', 'Low privileges are required to exploit the vulnerability.'),
            'High (H)': (0.27, 'H', 'High privileges are required to exploit the vulnerability.')
        },
        'help_text': 'Indicates the level of privileges an attacker needs to exploit the vulnerability.'
    },
    'UI': {
        'title': 'User Interaction',
        'options': {
            'None (N)': (0.85, 'N', 'No user interaction is required.'),
            'Required (R)': (0.62, 'R', 'User interaction is required, e.g., clicking a link.')
        },
        'help_text': 'Indicates whether exploiting the vulnerability requires user involvement, such as clicking a link.',
    },
    'S': {
        'title': 'Scope',
        'options': {
            'Unchanged (U)': (6.42, 'U', 'The impact remains within the original security domain.'),
            'Changed (C)': (7.52, 'C', 'The impact extends to other security domains.')
        },
        'help_text': 'Determines whether the vulnerability affects resources beyond the security authority of the vulnerable component.',
    },
    'C': {
        'title': 'Confidentiality Impact',
        'options': {
            'None (N)': (0.0, 'N', 'No impact on confidentiality.'),
            'Low (L)': (0.22, 'L', 'Limited impact on confidentiality.'),
            'High (H)': (0.56, 'H', 'Complete loss of confidentiality.')
        },
        'help_text': 'Assesses the potential impact on confidentiality.',
    },
    'I': {
        'title': 'Integrity Impact',
        'options': {
            'None (N)': (0.0, 'N', 'No impact on integrity.'),
            'Low (L)': (0.22, 'L', 'Limited impact on integrity.'),
            'High (H)': (0.56, 'H', 'Complete loss of integrity.')
        },
        'help_text': 'Assesses the potential impact on integrity.',
    },
    'A': {
        'title': 'Availability Impact',
        'options': {
            'None (N)': (0.0, 'N', 'No impact on availability.'),
            'Low (L)': (0.22, 'L', 'Limited impact on availability.'),
            'High (H)': (0.56, 'H', 'Complete loss of availability.')
        },
        'help_text': 'Assesses the potential impact on availability.',
    }
}