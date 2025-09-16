# passenger_wsgi.py
import sys
import os

# Add your project directory to the Python path
sys.path.insert(0, os.path.dirname(__file__))

# Set environment variables for production
os.environ.setdefault('FLASK_ENV', 'production')
os.environ.setdefault('DATABASE_URL', 'postgresql://optionpay_abhi:98603039859518337299@127.0.0.200:5432/optionpay_optionpay')
os.environ.setdefault('SECRET_KEY', 'your-production-secret-key-change-this')

try:
    # Import your existing Flask app
    from app import app
    
    # Expose as application for Passenger
    application = app
    
    # Ensure production settings
    application.config['DEBUG'] = False
    application.config['TESTING'] = False
    
    print("✅ Flask application loaded successfully for Passenger")
    
except Exception as e:
    print(f"❌ Error loading Flask application: {e}")
    import traceback
    traceback.print_exc()
    
    # Fallback WSGI application for debugging
    def application(environ, start_response):
        status = '500 Internal Server Error'
        response_headers = [('Content-type', 'text/html')]
        start_response(status, response_headers)
        error_html = f"""
        <html>
        <head><title>Application Error</title></head>
        <body>
            <h1>Application Error</h1>
            <p>Error loading Flask application: {str(e)}</p>
            <pre>{traceback.format_exc()}</pre>
        </body>
        </html>
        """
        return [error_html.encode()]

if __name__ == "__main__":
    application.run(debug=False)