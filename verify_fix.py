import sys
import os

# Add the project root to sys.path so we can import ml.predict
sys.path.append(os.getcwd())

try:
    from ml import predict
    print("Successfully imported ml.predict")
    
    # Access the private function for verification purposes
    classes = predict._get_onnx_classes()
    
    if classes:
        print(f"SUCCESS: Classes found! (Length: {len(classes)})")
        print(f"Sample classes: {classes[:3]}")
    else:
        print("FAILURE: Classes returned None (should have raised exception if detailed error handling worked, or returned list)")
        
except ImportError as e:
    print(f"ImportError: {e}")
except FileNotFoundError as e:
    print(f"FileNotFoundError: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
    import traceback
    traceback.print_exc()
