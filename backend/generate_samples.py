# generate_samples.py

# 1. Create the "EICAR" Test File (Standard Anti-Malware Test String)
# This string is harmless but ALL antivirus engines agree to treat it as a virus.
eicar_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

with open("fake_virus.exe", "w") as f:
    f.write(eicar_string)
print("[+] Created 'fake_virus.exe' (Safe test file that triggers alerts)")

# 2. Create a "Clean" Dummy File
# Just some random text pretending to be a program
clean_content = "This is a clean application. No malicious code here. System checks: OK. Graphics: OK."

with open("clean_app.exe", "w") as f:
    f.write(clean_content)
print("[+] Created 'clean_app.exe' (Safe file that should be marked Benign)")