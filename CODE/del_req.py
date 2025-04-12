import subprocess
import pkg_resources

# Define the required packages you want to keep
required = {
    "Flask",
    "Flask-SQLAlchemy",
    "python-dotenv",
    "WTForms",
    "Flask-WTF",
    "SQLAlchemy",
    "greenlet",
    "PyJWT",
    "email_validator",
}

# Get all installed packages
installed = {pkg.key for pkg in pkg_resources.working_set}

# Normalize and lowercase required package names
required_normalized = {pkg.lower() for pkg in required}

# Identify unwanted packages
unwanted = installed - required_normalized

if not unwanted:
    print("No packages to uninstall. You're all set!")
else:
    print("Uninstalling these packages:\n", "\n".join(sorted(unwanted)))
    subprocess.run(["pip", "uninstall", "-y", *sorted(unwanted)])
