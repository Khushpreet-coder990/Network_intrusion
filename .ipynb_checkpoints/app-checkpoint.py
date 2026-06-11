import streamlit as st
import pandas as pd
import numpy as np
import joblib

# 1. Page Configuration
st.set_page_config(
    page_title="Network Intrusion & DoS Detection System",
    page_icon="🛡️",
    layout="wide"
)

# 2. Load the Trained Model
@st.cache_resource
def load_model():
    try:
        # Load your saved model file
        model = joblib.load("cybersecurity_intrusion.pkl")
        return model
    except FileNotFoundError:
        st.error("⚠️ 'cybersecurity_intrusion.pkl' not found! Please place it in the same directory.")
        return None

model = load_model()

# 3. UI Header
st.title("🛡️ AI-Driven Network Intrusion Detection System")
st.markdown("""
This dashboard uses a trained Machine Learning model to analyze real-time network session data 
and predict potential **Intrusions or Denial of Service (DoS)** attacks.
---
""")

# 4. Sidebar Input Fields (Based on your CSV features)
st.sidebar.header("📊 Network Session Features")

network_packet_size = st.sidebar.number_input("Network Packet Size (Bytes)", min_value=0, max_value=10000, value=500, step=10)
protocol_type = st.sidebar.selectbox("Protocol Type", ["TCP", "UDP", "ICMP"]) # Update based on your exact training categories
login_attempts = st.sidebar.slider("Login Attempts", min_value=0, max_value=10, value=1)
session_duration = st.sidebar.number_input("Session Duration (Seconds)", min_value=0.0, max_value=86400.0, value=120.0, step=1.0)
encryption_used = st.sidebar.selectbox("Encryption Used", ["AES", "DES", "None"])
ip_reputation_score = st.sidebar.slider("IP Reputation Score (0 = Bad, 1 = Good)", min_value=0.0, max_value=5.0, value=0.8, step=0.01)
failed_logins = st.sidebar.slider("Failed Logins", min_value=0, max_value=10, value=0)
browser_type = st.sidebar.selectbox("Browser Type", ["Chrome", "Firefox", "Edge", "Safari", "Unknown"])
unusual_time_access = st.sidebar.selectbox("Unusual Time Access?", ["No", "Yes"])

# Convert human-readable select boxes to match model expectations (0 or 1)
unusual_time_numeric = 1 if unusual_time_access == "Yes" else 0

# 5. Data Structuring
# Create a dictionary matching your training features *exactly* in order
input_data = {
    'network_packet_size': network_packet_size,
    'protocol_type': protocol_type,
    'login_attempts': login_attempts,
    'session_duration': session_duration,
    'encryption_used': encryption_used,
    'ip_reputation_score': ip_reputation_score,
    'failed_logins': failed_logins,
    'browser_type': browser_type,
    'unusual_time_access': unusual_time_numeric,
   
}

# Convert to DataFrame
input_df = pd.DataFrame([input_data])

# 6. Display Input Metrics Layout
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("📥 Current Session Data")
    st.dataframe(input_df, use_container_width=True)

with col2:
    st.subheader("🔍 Analysis Trigger")
    predict_btn = st.button("Analyze Traffic", type="primary", use_container_width=True)


# 7. Prediction Logic
if predict_btn:
    if model is not None:
        try:
            # --- 1. ENGINEER FEATURES ---
            failed_login_ratio = failed_logins / (login_attempts + 1e-5)
            traffic_density = network_packet_size / (session_duration + 1e-5)
            risk_score_index = unusual_time_numeric * (1.0 - ip_reputation_score)

            # --- 2. BUILD THE RAW DATA ---
            raw_data = {
                'network_packet_size': float(network_packet_size),
                'login_attempts': int(login_attempts),
                'session_duration': float(session_duration),
                'ip_reputation_score': float(ip_reputation_score),
                'failed_logins': int(failed_logins),
                'unusual_time_access': int(unusual_time_numeric),
                'failed_login_ratio': float(failed_login_ratio),
                'traffic_density': float(traffic_density),
                'risk_score_index': float(risk_score_index),
                'protocol_type_TCP': 1 if protocol_type == "TCP" else 0,
                'protocol_type_UDP': 1 if protocol_type == "UDP" else 0,
                'encryption_used_DES': 1 if encryption_used == "DES" else 0,
                'browser_type_Edge': 1 if browser_type == "Edge" else 0,
                'browser_type_Firefox': 1 if browser_type == "Firefox" else 0,
                'browser_type_Safari': 1 if browser_type == "Safari" else 0,
                'browser_type_Unknown': 1 if browser_type == "Unknown" else 0
            }
            
            # --- 3. FORMAT AS 16-COLUMN DATAFRAME ---
            input_df = pd.DataFrame([raw_data])
            expected_features = [
                'network_packet_size', 'login_attempts', 'session_duration', 
                'ip_reputation_score', 'failed_logins', 'unusual_time_access', 
                'failed_login_ratio', 'traffic_density', 'risk_score_index',
                'protocol_type_TCP', 'protocol_type_UDP',
                'encryption_used_DES',
                'browser_type_Edge', 'browser_type_Firefox', 
                'browser_type_Safari', 'browser_type_Unknown'
            ]
            input_df = input_df[expected_features]

            # ==========================================
            # 🛑 CRITICAL SCALER STEP GOES HERE LATER
            # ==========================================

            # --- 4. PREDICT USING .values (Strips column names to match model) ---
            # Using .values prevents the feature_names_in_ error
            prediction = model.predict(input_df.values)
            
            if hasattr(model, "predict_proba"):
                probabilities = model.predict_proba(input_df.values)[0]
                confidence = np.max(probabilities) * 100
            else:
                confidence = None

            st.subheader("📋 Analysis Result")

            if prediction[0] == 1:
                st.error(f"🚨 **CRITICAL WARNING:** Attack Detected!")
            else:
                st.success(f"✅ **SAFE:** Traffic patterns appear completely normal.")

        except Exception as e:
            st.error(f"Prediction Error: {str(e)}")   