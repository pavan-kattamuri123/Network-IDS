# Network-IDS
A Flask-based Network Intrusion Detection System (NIDS) that uses machine learning to analyze network traffic and identify threats. Features include CSV data uploads, real-time prediction, a visualization dashboard for monitoring attack types, and cloud-integrated history tracking via MongoDB Atlas for comprehensive network security analytics.


Network Intrusion Detection System (NIDS):

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
- **Extended Dataset Training**: Incorporating more recent datasets (e.g., CICIDS 2024 or CSE-CIC-IDS2018) to keep pace with evolving threat landscapes
