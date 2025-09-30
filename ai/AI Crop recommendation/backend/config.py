import os

class Config:
    # Secret key for session management
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this-in-production'
    
    # Database configuration
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database', 'users.db')
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    
    # Model path
    MODEL_PATH = os.path.join(os.path.dirname(__file__), 'crop_model.pkl')