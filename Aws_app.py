from flask import Flask, render_template_string, request, redirect, url_for, session, flash
import boto3
from botocore.exceptions import ClientError
import uuid
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key')

# AWS Configuration
AWS_REGION = 'us-east-1'
USERS_TABLE = 'travel_user'
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:604665149129:fixitnow_Topic"

# AWS Initialization
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sns_client = boto3.client('sns', region_name=AWS_REGION)
users_table = dynamodb.Table(USERS_TABLE)

# ------------ HTML Templates (inline) ------------

home_template = """
<!DOCTYPE html>
<html>
<head><title>TravelGo - Home</title></head>
<body>
    <h1>Welcome to TravelGo</h1>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <ul>{% for message in messages %}<li>{{ message }}</li>{% endfor %}</ul>
        {% endif %}
    {% endwith %}
    <a href="{{ url_for('login') }}">Login</a> |
    <a href="{{ url_for('register') }}">Register</a>
</body>
</html>
"""

register_template = """
<!DOCTYPE html>
<html>
<head><title>Register - TravelGo</title></head>
<body>
    <h2>Register for TravelGo</h2>
    <form method="POST">
        <label>Username:</label><input type="text" name="username" required><br><br>
        <label>Email:</label><input type="email" name="email" required><br><br>
        <label>Password:</label><input type="password" name="password" required><br><br>
        <button type="submit">Register</button>
    </form>
    <p>Already have an account? <a href="{{ url_for('login') }}">Login</a></p>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <ul>{% for message in messages %}<li>{{ message }}</li>{% endfor %}</ul>
        {% endif %}
    {% endwith %}
</body>
</html>
"""

login_template = """
<!DOCTYPE html>
<html>
<head><title>Login - TravelGo</title></head>
<body>
    <h2>Login</h2>
    <form method="POST">
        <label>Email:</label><input type="email" name="email" required><br><br>
        <label>Password:</label><input type="password" name="password" required><br><br>
        <button type="submit">Login</button>
    </form>
    <p>No account? <a href="{{ url_for('register') }}">Register here</a></p>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <ul>{% for message in messages %}<li>{{ message }}</li>{% endfor %}</ul>
        {% endif %}
    {% endwith %}
</body>
</html>
"""

dashboard_template = """
<!DOCTYPE html>
<html>
<head><title>Dashboard - TravelGo</title></head>
<body>
    <h2>Welcome, {{ user }}!</h2>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <ul>{% for message in messages %}<li>{{ message }}</li>{% endfor %}</ul>
        {% endif %}
    {% endwith %}
    <form method="POST" action="{{ url_for('notify') }}">
        <label>Send Notification:</label><br>
        <textarea name="message" rows="4" cols="50" required></textarea><br><br>
        <button type="submit">Send</button>
    </form>
    <br>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
"""

# ---------------- Routes ----------------

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        try:
            users_table.put_item(
                Item={
                    'user_id': str(uuid.uuid4()),
                    'username': username,
                    'email': email,
                    'password': password
                }
            )
            flash('User registered successfully!')
            return redirect(url_for('login'))
        except ClientError as e:
            flash(f"Registration failed: {e.response['Error']['Message']}")
            return redirect(url_for('register'))

    return render_template_string(register_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            response = users_table.scan(
                FilterExpression="email = :e AND password = :p",
                ExpressionAttributeValues={":e": email, ":p": password}
            )
            users = response.get('Items', [])

            if users:
                session['user'] = users[0]['username']
                flash('Login successful!')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials')
                return redirect(url_for('login'))

        except ClientError as e:
            flash(f"Login error: {e.response['Error']['Message']}")
            return redirect(url_for('login'))

    return render_template_string(login_template)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template_string(dashboard_template, user=session['user'])

@app.route('/notify', methods=['POST'])
def notify():
    if 'user' not in session:
        return redirect(url_for('login'))

    message = request.form['message']
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject='TravelGo Notification'
        )
        flash("Notification sent!")
    except ClientError as e:
        flash(f"Notification failed: {e.response['Error']['Message']}")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for('home'))

# --------------- Main ----------------
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
