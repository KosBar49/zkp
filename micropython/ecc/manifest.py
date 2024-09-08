include("$(BOARD_DIR)/manifest.py")
# Add a custom driver
module("mydriver.py")
# Add aiorepl from micropython-lib
require("aiorepl")