![image](https://github.com/user-attachments/assets/cf519e5b-fd85-4b63-9c97-99323702c988)

# techScanner

## Overview

Asset Technology Scanner is a command-line tool designed to scan web assets and detect the technologies they use. It leverages the WhatRuns and Wappalyzer APIs to provide insights into the tech stack of a given domain.

## Features

-   Detects technologies using the **WhatRuns API**.
    
-   Identifies frameworks, CMS, and other tech components with **Wappalyzer**.
    
-   Supports scanning a **single asset** or a **list of assets from a file**.
    
-   Outputs results in a **CSV file**.
    
-   Displays results in a **tabular format** in the terminal.

## Installation

Ensure you have Python installed on your system. Then, install the required dependencies:

```
pip install -r requirements.txt
```

## Usage

### Scan a Single Asset

```
python techScanner.py --asset example.com --wf results.csv
```

### Scan Multiple Assets from a File

```
python techScanner.py --file assets.txt --wf results.csv
```

## POC
![image](https://github.com/user-attachments/assets/39082818-a207-4fc6-a55a-5c3ddc7cdd5d)


## Output

The tool saves the results in a `scandata` directory as a CSV file. The output includes:

-   Asset (domain scanned)
    
-   Source (WhatRuns / Wappalyzer)
    
-   Technology Type
    
-   Technology Name
    
-   Detection Timestamp (if available)
    
-   Last Detected Timestamp (if available)
    
-   Version (if applicable)
    

## Example Output

```
Asset       Source      Type              Name       Detected     Last_Detected Version
example.com Wappalyzer CMS               WordPress  N/A          N/A           5.8.1
example.com WhatRuns   JavaScript Lib    jQuery     2024-01-10   2024-02-15    3.6.0
```

## Notes

-   The **WhatRuns API** requires a valid connection and may have request limitations.
    
-   The **Wappalyzer module** performs fingerprinting based on HTTP responses and scripts.
    
-   Errors encountered during scanning are displayed in the terminal.
    

## Author

Developed by **Anmol K Sachan** (@FR13ND0x7F)

## License

This project is open-source. Feel free to use and modify it as needed.
