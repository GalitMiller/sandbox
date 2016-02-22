
# Address of read-only git repository with sensor rules for Suricata.
GIT_REPO_URL="https://cmc/git/rules.git"

# Default branch for sensor, when no rules were changed.
GIT_SENSOR_BRANCH="master"

# Subfolder within /etc/suricata (or other correspoding directory) where ProAccel will store its rule set.
# It should be different from a standard suricata rules directory to avoid their overwrite by
# nightly rules update job.
SURICATA_RULES_DIR="rules.bpac"
