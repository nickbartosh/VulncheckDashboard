# VulnCheck Dashboard
The Vulncheck Dashboard is a lightweight dashboard that provides organizations an easy interface to review
vulnerabilities based on provided CPEs

## Installation Instructions

** Prerequisites **
- Python 3.9+

** Installation Steps **
1. git clone https://github.com/nickbartosh/VulncheckDashboard.git
2. cd VulncheckDashboard
3. python3 -m venv venv
4. source venv/bin/activate
5. pip install -r requirements.txt
6. python3 app.py
7. Open your favorite Browser < http://127.0.0.1:5000/ >

## Usage 
- browse to Inventory
- Click the Add a New Asset Button
- Add the CPE String, Asset Name, Type etc..
- Select the "Sync vulnerabilities from VulnCheck after adding"
- Click "Add Asset"
- Rinse and repeat for additional assets
- Review Findings in Dashboard and vulnerabilities tab
