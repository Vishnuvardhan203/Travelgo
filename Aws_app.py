from flask import Flask, render_template, request, redirect, url_for, session, flash
import boto3
from botocore.exceptions import ClientError
import uuid
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key')

# AWS Configuration
AWS_REGION = 'us-east-1'
USERS_TABLE = 'travel_user'
SERVICES_TABLE = 'travel_service'
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:604665149129:fixitnow_Topic"

# Initialize AWS services
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sns_client = boto3.client('sns', region_name=AWS_REGION)

users_table = dynamodb.Table(USERS_TABLE)
services_table = dynamodb.Table(SERVICES_TABLE)

# ---------- Routes -------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    try:
        users_table.put_item(
            Item={
                'user_id': str(uuid.uuid4()),
                'username': username,
                'email': email,
                'password': password  # In real app, hash this!
            }
        )
        flash('User registered successfully!')
        return redirect(url_for('login'))
    except ClientError as e:
        flash(f"Registration failed: {e.response['Error']['Message']}")
        return redirect(url_for('home'))

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

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'])

@app.route('/notify', methods=['POST'])
def notify():
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

# ----------- Main ------------
if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=5000)
