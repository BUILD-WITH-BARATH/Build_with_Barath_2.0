# Independent validation kit

This is a protocol, not evidence by itself. Give the unmodified project folder to a friend, mentor, or security practitioner who was not involved in building it.

1. Ask the tester to run `py benchmark.py` and save the terminal output plus the generated `results/` folder.
2. Ask them to run their own manual sequences in Swagger, including different record IDs, mixed valid and invalid access, and an expired delegation.
3. They should record the date, their role (for example, “independent student tester”), the scenarios they chose, and whether any result contradicted the claims.
4. Do not edit the benchmark result after they run it. Add their signed notes and the exact commit/archive checksum to the submission.

Suggested independent tester questions:

* Can an unauthorised person retrieve data before the behavioural block activates? (Expected: no; authorization denies all such requests.)
* Does a valid temporary delegation show a reason, approver, and expiry? (Expected: yes.)
* Does a rapid legitimate sequence of assigned records get blocked? (Expected: no.)
* Is an expired delegation denied? (Expected: yes.)
* Does the fourth distinct unauthorised request in a fresh campaign show a behavioural BOLA block? (Expected: yes.)

Report the tester as an independent rerun of a **synthetic prototype**, not as a professional penetration test unless that is actually true.
