# 🛡️ CrowdStrike Container Security Image Assessment Export Tool

## 🌟 Overview
This tool automates the process of exporting image assessment data from CrowdStrike's Container Security API, featuring real-time progress visualization and comprehensive data handling.

## ✨ Features
- 🔄 Automated export job creation and management
- 📊 Real-time progress visualization with spinner animation
- 🚦 Visual status indicators (✓, ✗, ⚠)
- 📈 Progress tracking [current/total]
- 🔍 Detailed debug mode (optional)
- 💾 Multiple output formats (JSON and CSV)
- ⏱️ Rate limiting handling with visual countdown
- 🛡️ Comprehensive error handling and recovery

## Example Run

<img width="504" height="273" alt="image" src="https://github.com/user-attachments/assets/55fcd017-ed55-424d-9e23-dc6e6702ef67" />


## 🚀 Prerequisites
- Python 3.6+
- CrowdStrike API Client ID and Secret with Container Security access
- Required Python packages:
  ```bash
  pip install requests
  ```

## 📦 Installation
1. Clone the repository:
   ```bash
   git clone [repository-url]
   cd crowdstrike-container-assessment-export
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure your credentials:
   ```python
   client_id = "YOUR_CLIENT_ID"
   client_secret = "YOUR_CLIENT_SECRET"
   ```

## 🎮 Usage
1. Enable debug mode (optional):
   ```python
   DEBUG_MODE = True  # At top of script
   ```

2. Run the script:
   ```bash
   python3 cs_image_assessment.py
   ```

## 📊 Visual Indicators
- ✓ Success
- ✗ Failure/Error
- ⚠ Warning/Retry
- 🚀 Process Start
- 📊 Progress Update
- ⏱️ Countdown Timer
- 📦 Processing Status
- ✨ Completion

## 📂 Output Files
- `raw_export_data.json`: Raw data from API responses
- `combined_export_report.json`: Processed data with metadata
- `combined_export_report.csv`: Flattened data in CSV format

## 🔄 Process Flow
1. Authentication with visual feedback
2. For each hex pattern (0-9, a-f):
   - Create export job with spinner
   - Monitor job status with progress
   - Download results with visual feedback
3. Combine and validate all data
4. Generate output files with progress indication

## ⚙️ Configuration Options
```python
DEBUG_MODE = False        # Enable/disable debug output
self.LIMIT = 100         # Results per page
self.MAX_OFFSET = 10000  # Maximum pagination offset
max_attempts = 20        # Maximum retry attempts
```

## 📝 Debug Mode
Enable detailed output by setting `DEBUG_MODE = True`:
- API request details
- Response content
- Data processing information
- Error details
- Progress tracking

## 🔧 Error Handling
- Visual indicators for different error types
- Automatic retry with countdown
- Rate limit handling with waiting period
- Token refresh management
- Network error recovery

## 💡 Progress Tracking
- Real-time spinner animation
- Pattern progress [current/total]
- Records collected counter
- Time-remaining indicators
- Status symbols for each operation

## ⚠️ Known Limitations
- Maximum offset of 10000 records
- Rate limiting of concurrent jobs
- API timeout constraints

## 🤝 Contributing
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## 📜 License
MIT

## 👨‍💻 Author
@mikedzikowski/@crowdstrike

## 🙏 Acknowledgments
- CrowdStrike API Documentation

## 💬 Support
For issues and feature requests, please use the GitHub issue tracker.

## ⚠️ Disclaimer
This is not an official CrowdStrike tool. Use at your own risk and ensure compliance with CrowdStrike's API terms of service.

## 📈 Version History
- 1.1.0
  - Added real-time progress visualization
  - Added spinner animation
  - Enhanced status indicators
  - Improved error handling
  - Added visual countdown timers
- 1.0.0
  - Initial release
  - Basic export functionality
  - JSON and CSV output support

---

Made with ❤️ for the CrowdStrike Community

---

