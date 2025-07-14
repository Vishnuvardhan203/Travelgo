from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

app = Flask(__name__)
app.secret_key = 'e0d15ae2faa18025f4e2a0c7dc5a7b8a830791cc83ad7538667ce14ca2ad8bc0'  # Change for production!

# MySQL Config (replace with your actual credentials)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:Password@localhost:3306/travelgo'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ------------------------
# Database Models
# ------------------------



class User(db.Model):
    __tablename__ = 'users'
    email = db.Column(db.String(100), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    logins = db.Column(db.Integer, default=0)

# class Booking(db.Model):
#     __tablename__ = 'bookings'
#     booking_id = db.Column(db.String(100), primary_key=True)
#     user_email = db.Column(db.String(100), db.ForeignKey('users.email'), nullable=False)
#     booking_type = db.Column(db.String(50))
#     booking_date = db.Column(db.DateTime, default=datetime.utcnow)
#     name = db.Column(db.String(100))
#     source = db.Column(db.String(100))
#     destination = db.Column(db.String(100))
#     travel_date = db.Column(db.String(100))
#     seats_display = db.Column(db.String(100))
#     total_price = db.Column(db.Float)
#     status = db.Column(db.String(50))
#     item_id = db.Column(db.String(100))        # For bus bookings
#     train_number = db.Column(db.String(50))    # For train bookings
#     location = db.Column(db.String(100))       # For hotel bookings
#     checkin_date = db.Column(db.String(100))
#     checkout_date = db.Column(db.String(100))
#     num_guests = db.Column(db.Integer)
#     room_type = db.Column(db.String(100))


from datetime import datetime

class Booking(db.Model):
    __tablename__ = 'bookings'
    booking_id = db.Column(db.String(100), primary_key=True)
    user_email = db.Column(db.String(100), db.ForeignKey('users.email'), nullable=False)
    booking_type = db.Column(db.String(50))
    booking_date = db.Column(db.DateTime, default=datetime.utcnow)
    name = db.Column(db.String(100))
    source = db.Column(db.String(100))
    destination = db.Column(db.String(100))
    travel_date = db.Column(db.String(100))
    seats_display = db.Column(db.String(100))
    total_price = db.Column(db.Float)
    status = db.Column(db.String(50))
    item_id = db.Column(db.String(100))        # For bus bookings
    train_number = db.Column(db.String(50))    # For train bookings
    location = db.Column(db.String(100))       # For hotel bookings
    checkin_date = db.Column(db.String(100))
    checkout_date = db.Column(db.String(100))
    num_guests = db.Column(db.Integer)
    room_type = db.Column(db.String(100))

    def to_dict(self):
        return {
            'booking_id': self.booking_id,
            'user_email': self.user_email,
            'booking_type': self.booking_type,
            'booking_date': self.booking_date.isoformat() if self.booking_date else None,
            'name': self.name,
            'source': self.source,
            'destination': self.destination,
            'travel_date': self.travel_date,
            'seats_display': self.seats_display,
            'total_price': self.total_price,
            'status': self.status,
            'item_id': self.item_id,
            'train_number': self.train_number,
            'location': self.location,
            'checkin_date': self.checkin_date,
            'checkout_date': self.checkout_date,
            'num_guests': self.num_guests,
            'room_type': self.room_type
        }


# ------------------------
# Fake SNS notification sender (replace with your actual SNS logic)
# ------------------------
def send_sns_notification(subject, message):
    # Here just print - replace with your AWS SNS logic if needed
    print(f"[SNS] {subject}\n{message}\n")

# ------------------------
# Routes
# ------------------------

@app.route('/')
def home():
    return render_template('index.html', logged_in='email' in session)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash('User already exists!', 'error')
            return render_template('register.html')

        hashed_password = generate_password_hash(password)
        new_user = User(email=email, name=name, password=hashed_password, logins=0)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['email'] = email
            session['user_name'] = user.name

            user.logins += 1
            db.session.commit()

            #flash('Login successful! Welcome back.', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid email or password. Please try again.', 'error')
        return render_template('login.html')

    return render_template('login.html')

# @app.route('/dashboard')
# def dashboard():
#     if 'email' not in session:
#         return redirect(url_for('login'))

#     user_email = session['email']
#     bookings = Booking.query.filter_by(user_email=user_email).order_by(Booking.booking_date.desc()).all()

#     return render_template('dashboard.html', username=user_email, bookings=bookings)


@app.route('/dashboard')
def dashboard():
    user_email = session.get('user_email')
    bookings = Booking.query.filter_by(user_email=user_email).all()

    # Convert each Booking object to a dictionary
    booking_dicts = [b.to_dict() for b in bookings]

    return render_template('dashboard.html', username=user_email, bookings=booking_dicts)


@app.route('/logout')
def logout():
    session.clear()
    #flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

# ------------------------
# Booking pages (just render templates)
# ------------------------

@app.route('/bus')
def bus_booking():
    if 'email' not in session:
        flash('Please login to book tickets.', 'error')
        return redirect(url_for('login'))
    return render_template('bus.html')

@app.route('/train')
def train_booking():
    if 'email' not in session:
        flash('Please login to book tickets.', 'error')
        return redirect(url_for('login'))
    return render_template('train.html')

@app.route('/flight')
def flight_booking():
    if 'email' not in session:
        flash('Please login to book tickets.', 'error')
        return redirect(url_for('login'))
    return render_template('flight.html')

@app.route('/hotel')
def hotel_booking():
    if 'email' not in session:
        flash('Please login to book tickets.', 'error')
        return redirect(url_for('login'))
    return render_template('hotel.html')

# ------------------------
# Bus Booking Flow
# ------------------------

@app.route('/confirm_bus_details')
def confirm_bus_details():
    if 'email' not in session:
        return redirect(url_for('login'))

    booking_details = {
        'name': request.args.get('name'),
        'source': request.args.get('source'),
        'destination': request.args.get('destination'),
        'time': request.args.get('time'),
        'type': request.args.get('type'),
        'price_per_person': float(request.args.get('price')),
        'travel_date': request.args.get('date'),
        'num_persons': int(request.args.get('persons')),
        'item_id': request.args.get('busId'),
        'booking_type': 'bus',
        'user_email': session['email'],
        'total_price': float(request.args.get('price')) * int(request.args.get('persons'))
    }

    session['pending_booking'] = booking_details
    return render_template("bus.html", booking=booking_details)

@app.route('/api/book_bus', methods=['POST'])
def api_book_bus():
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    booking_data = Booking(
        user_email=session['email'],
        booking_type='bus',
        booking_id=str(uuid.uuid4()),
        booking_date=datetime.now(),
        name=data.get('busName'),
        source=data.get('from'),
        destination=data.get('to'),
        travel_date=data.get('date'),
        seats_display=data.get('seat'),
        total_price=float(data.get('price', 0)),
        status=data.get('status', 'Confirmed'),
        item_id=data.get('busId')
    )

    try:
        db.session.add(booking_data)
        db.session.commit()

        send_sns_notification(
            subject="Bus Booking Confirmed",
            message=f"Dear {booking_data.user_email},\nYour bus booking is confirmed.\nSeats: {booking_data.seats_display}\nTotal Price: ₹{booking_data.total_price}"
        )

        return jsonify({'message': 'Bus booked successfully!'}), 200
    except Exception as e:
        print(f"Error booking bus: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/final_confirm_bus_booking', methods=['POST'])
def final_confirm_bus_booking():
    if 'email' not in session:
        return redirect(url_for('login'))

    booking = session.pop('pending_booking', None)
    selected_seats_str = request.form.get('selected_seats')

    if not booking or not selected_seats_str:
        flash("Booking failed! Missing data or session expired.", "error")
        return redirect(url_for("bus_booking"))

    selected_seats = set(selected_seats_str.split(', '))

    # Check seat availability
    try:
        existing_bookings = Booking.query.filter_by(
            item_id=booking['item_id'],
            travel_date=booking['travel_date'],
            booking_type='bus'
        ).all()

        existing_booked_seats = set()
        for b in existing_bookings:
            if b.seats_display:
                existing_booked_seats.update(b.seats_display.split(', '))

        if selected_seats.intersection(existing_booked_seats):
            flash("One or more selected seats are already booked. Please choose again.", "error")
            session['pending_booking'] = booking
            return redirect(url_for('bus_booking'))

        # Finalize booking
        new_booking = Booking(
            booking_id=str(uuid.uuid4()),
            user_email=booking['user_email'],
            booking_type='bus',
            booking_date=datetime.now(),
            name=booking['name'],
            source=booking['source'],
            destination=booking['destination'],
            travel_date=booking['travel_date'],
            seats_display=selected_seats_str,
            total_price=booking['total_price'],
            status='Confirmed',
            item_id=booking['item_id']
        )
        db.session.add(new_booking)
        db.session.commit()

        send_sns_notification(
            subject="Bus Booking Confirmed",
            message=f"Dear {new_booking.user_email},\nYour bus from {new_booking.source} to {new_booking.destination} on {new_booking.travel_date} is confirmed.\nSeats: {new_booking.seats_display}\nTotal Price: ₹{new_booking.total_price}"
        )

        flash('Bus booking confirmed successfully!', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        print(f"Error confirming bus booking: {e}")
        flash(f"Failed to confirm booking: {e}", 'error')
        return redirect(url_for("bus_booking"))

# ------------------------
# Train Booking API
# ------------------------

@app.route('/api/book_train', methods=['POST'])
def api_book_train():
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    booking_data = Booking(
        user_email=session['email'],
        booking_type='train',
        booking_id=str(uuid.uuid4()),
        booking_date=datetime.now(),
        name=data.get('trainName'),
        train_number=data.get('trainNumber'),
        source=data.get('from'),
        destination=data.get('to'),
        travel_date=data.get('date'),
        seats_display=data.get('seat'),
        total_price=float(data.get('price', 0)),
        status='Confirmed'
    )

    try:
        db.session.add(booking_data)
        db.session.commit()

        send_sns_notification(
            subject="Train Booking Confirmed",
            message=f"Dear {booking_data.user_email},\nYour train booking is confirmed.\nTrain: {booking_data.name} ({booking_data.train_number})\nSeats: {booking_data.seats_display}\nTotal Price: ₹{booking_data.total_price}"
        )

        return jsonify({'message': 'Train booked successfully!'}), 200
    except Exception as e:
        print(f"Error booking train: {e}")
        return jsonify({'error': str(e)}), 500

# ------------------------
# Flight Booking
# ------------------------

@app.route('/book_flight', methods=['POST'])
def book_flight():
    if 'email' not in session:
        return redirect(url_for('login'))

    booking_data = Booking(
        user_email=session['email'],
        booking_type='flight',
        booking_id=str(uuid.uuid4()),
        booking_date=datetime.now(),
        source=request.form.get('from'),
        destination=request.form.get('to'),
        travel_date=request.form.get('date'),
        seats_display=request.form.get('seat'),
        total_price=float(request.form.get('price', 0)),
        status='Confirmed',
        name=request.form.get('airlineName')
    )

    try:
        db.session.add(booking_data)
        db.session.commit()

        send_sns_notification(
            subject="Flight Booking Confirmed",
            message=f"Dear {booking_data.user_email},\nYour flight booking is confirmed.\nAirline: {booking_data.name}\nSeats: {booking_data.seats_display}\nTotal Price: ₹{booking_data.total_price}"
        )

        flash('Flight booked successfully!', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        print(f"Error booking flight: {e}")
        flash(f"Booking failed: {e}", 'error')
        return redirect(url_for('flight_booking'))

# ------------------------
# Hotel Booking API
# ------------------------

@app.route('/api/book_hotel', methods=['POST'])
def api_book_hotel():
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    booking_data = Booking(
        user_email=session['email'],
        booking_type='hotel',
        booking_id=str(uuid.uuid4()),
        booking_date=datetime.now(),
        name=data.get('hotelName'),
        location=data.get('location'),
        checkin_date=data.get('checkin'),
        checkout_date=data.get('checkout'),
        num_guests=int(data.get('numGuests', 1)),
        room_type=data.get('roomType'),
        total_price=float(data.get('price', 0)),
        status='Confirmed'
    )

    try:
        db.session.add(booking_data)
        db.session.commit()

        send_sns_notification(
            subject="Hotel Booking Confirmed",
            message=f"Dear {booking_data.user_email},\nYour hotel booking is confirmed.\nHotel: {booking_data.name}\nLocation: {booking_data.location}\nCheck-in: {booking_data.checkin_date}\nCheck-out: {booking_data.checkout_date}\nTotal Price: ₹{booking_data.total_price}"
        )

        return jsonify({'message': 'Hotel booked successfully!'}), 200
    except Exception as e:
        print(f"Error booking hotel: {e}")
        return jsonify({'error': str(e)}), 500

# ------------------------
# Cancel Booking
# ------------------------

@app.route('/cancel_booking/<booking_id>', methods=['POST'])
def cancel_booking(booking_id):
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_email = session['email']

    booking = Booking.query.filter_by(user_email=user_email, booking_id=booking_id).first()
    if not booking:
        flash("Booking not found or already cancelled.", "error")
        return redirect(url_for('dashboard'))

    try:
        db.session.delete(booking)
        db.session.commit()
        flash("Booking cancelled successfully!", "success")
    except Exception as e:
        flash(f"Failed to cancel booking: {e}", "error")

    return redirect(url_for('dashboard'))

# ------------------------
# Run the app
# ------------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure tables exist
    app.run(debug=True)
