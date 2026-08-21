"""Red team agent for CyberRanger Arena.

Emits attack (and benign) actions one at a time. In stage 1 this is a
hardcoded playbook; later stages swap next_action() for an LLM policy.
"""


class RedAgent:
    """Scripted attacker that iterates over a fixed playbook of actions.

    Each action is a dict: {name, category, payload, target_field}.
    category is one of: 'sqli', 'xss', 'benign' (used as ground truth).
    """

    def __init__(self):
        # A small, honest playbook: 2 SQLi, 2 XSS, 1 benign.
        self._playbook = [
            {
                "name": "SQLi login bypass (OR 1=1)",
                "category": "sqli",
                "payload": "admin' OR '1'='1",
                "target_field": "username",
            },
            {
                "name": "SQLi UNION probe",
                "category": "sqli",
                "payload": "1' UNION SELECT user,password FROM users -- -",
                "target_field": "id",
            },
            {
                "name": "XSS reflected <script>",
                "category": "xss",
                "payload": "<script>alert('xss')</script>",
                "target_field": "name",
            },
            {
                "name": "XSS img onerror",
                "category": "xss",
                "payload": "<img src=x onerror=alert(1)>",
                "target_field": "name",
            },
            {
                "name": "Benign lookup",
                "category": "benign",
                "payload": "hello world",
                "target_field": "name",
            },
        ]
        self._i = 0

    def next_action(self):
        """Return the next action dict from the playbook (cycles round-robin).

        This is the single seam where a smarter policy plugs in.
        """
        # LLM policy plugs in here: replace the round-robin below with a call
        # to a language-model policy that chooses the next payload from
        # observed feedback (breaches, blue detections, response contents).
        action = self._playbook[self._i % len(self._playbook)]
        self._i += 1
        return dict(action)  # copy so callers can't mutate the playbook
