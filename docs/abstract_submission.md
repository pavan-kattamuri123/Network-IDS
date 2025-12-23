# Abstract Submission

## Project Title
   Network Intrusion Detection System (NIDS)

## Abstract
In the modern digital landscape, the exponential rise in cyberattacks and their increasing sophistication have rendered traditional security measures inadequate. This project presents a robust and scalable Network Intrusion Detection System (NIDS) designed to identify, classify, and mitigate unauthorized activities within a network environment in real-time.

The core of the system utilizes a **Random Forest** machine learning algorithm, trained on the comprehensive **CICIDS 2017 dataset**. This choice of algorithm ensures high accuracy and stability across a variety of attack vectors, including Denial of Service (DoS), Port Scanning, Botnet activity, and Web-based attacks. To optimize for performance and cross-platform deployment, the model is exported to the **ONNX (Open Neural Network Exchange)** format, enabling high-speed inference via the ONNX Runtime with minimal CPU overhead.

The application architecture features a lightweight **Flask** web framework for the backend, providing a responsive and intuitive user interface for traffic monitoring and analysis. A key innovation of this system is its integration with **MongoDB Atlas**, a cloud-native database. This allows for centralized, persistent storage of attack history and model metadata, facilitating remote monitoring and ensuring data availability across diverse environments.

Evaluation of the system demonstrates high precision and recall in detecting multi-class network threats. By combining modern machine learning techniques with cloud-native infrastructure, this project offers a highly effective, scalable, and user-centric solution for enhancing cybersecurity posture in contemporary network infrastructures.

## Keywords
Network Intrusion Detection System (NIDS), Machine Learning, Random Forest, Flask, MongoDB Atlas, Cybersecurity, ONNX Runtime, Network Security.

## Technical Specifications
- **Machine Learning Layer**: Random Forest Classifier with 100 estimators.
- **Model Optimization**: ONNX format for efficient cross-platform execution.
- **Backend Framework**: Python Flask.
- **Database Architecture**: MongoDB Atlas (Cloud-based storage).
- **Communication Protocol**: RESTful API for frontend-backend interaction.
- **Data Source Compatibility**: Support for CICIDS 2017 standard network flow formats.

## Future Scope
- **Real-Time Traffic Analysis**: Integration of Scapy or PyShark for live packet capture and analysis.
- **Deep Learning Integration**: Implementation of LSTM or CNN models for analyzing sequential patterns in network traffic.
- **Automated Response System**: Development of an automated alert and mitigation system (e.g., automated firewall rule updates).
- **Extended Dataset Training**: Incorporating more recent datasets (e.g., CICIDS 2024 or CSE-CIC-IDS2018) to keep pace with evolving threat landscapes.


















what are the key differences between existing/traditional projects and your project?


Based on the architecture of your project and the common standards for Network Intrusion Detection Systems (NIDS), here are the key differences between existing/traditional projects and your project:

1. Detection Methodology

Existing Projects: Often rely on Signature-based detection (e.g., Snort). These systems search for specific strings or patterns in traffic. If an attack is new (Zero-day) and doesn't have a signature yet, it goes undetected.
Our Project: Uses Anomaly-based Machine Learning (Random Forest). By training on the CICIDS 2017 dataset, the system learns the behavior of attacks. This allows it to identify suspicious patterns even if they don't match a pre-defined signature.


2. Deployment Philosophy (ONNX Integration)

Existing Projects: Many ML-based IDS projects use "Pickle" files to save models. Pickle is insecure (can execute arbitrary code) and tied to specific Python versions.
Our Project: Uses the ONNX (Open Neural Network Exchange) format. This makes your model:
Faster: ONNX Runtime is highly optimized for inference speed.
Portable: The model can be run on different hardware (CPU/GPU) or even exported to other languages (C++, Java) in the future without retraining.
Secure: Unlike Pickle, ONNX is a data-only format.



3. Cloud-Native Storage (MongoDB Atlas)

Existing Projects: Most open-source NIDS store logs in local text files or local databases (like SQLite or MySQL). This makes it harder to monitor multiple networks from a single location.
Our Project: Integrated with MongoDB Atlas. This provides:
Centralized Monitoring: You can view attack history from anywhere in the world.
Scalability: The system isn't limited by your local hard drive space; it can handle millions of logs across the cloud.
Model-as-a-Service: Your project is designed to fetch the latest model directly from the cloud, allowing for remote updates without redeploying the app.




4. User Experience & Dashboard

Existing Projects: Often require complex command-line knowledge or heavy "SIEM" tools (like ELK Stack) to visualize data.
Our Project: Includes a built-in Flask dashboard. It simplifies the process—anyone can upload a traffic file and immediately see a visual breakdown of threats and benign traffic without needing to be a cybersecurity expert.

Summary Table
Feature=Traditional/Existing NIDS	Our Project
Logic=Fixed Signatures/Rules	Machine Learning (Random Forest)
Model Format=Hardcoded or Pickle	ONNX (Optimized & Secure)
Storage= Local Files/Local DB	Cloud-native (MongoDB Atlas)
Interface=CLI / Complex Logs	Web Dashboard (Flask)
Flexibility=Static	Dynamic behavior detection
These differences make your project more scalable, portable, and future-proof compared to standard localized IDS implementations.