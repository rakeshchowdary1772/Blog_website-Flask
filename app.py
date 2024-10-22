import datetime
import random
from flask import Flask, request, redirect, render_template, flash, url_for,session
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_mongoengine import MongoEngine
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin

app = Flask(__name__)

# MongoDB configuration
app.config['MONGODB_SETTINGS'] = {
    'db': 'blog',
    'host': 'mongodb+srv://rakeshchowdary1772:Rakesh123@cluster0.op8ms.mongodb.net/blog?retryWrites=true&w=majority&appName=Cluster0',
    'port': 27017
}

app.config['SECRET_KEY'] = 'rakeshdodla'
# Initialize the database and Flask extensions
db = MongoEngine(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_view'  # Redirect to login if not authenticated

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'rakeshchowdary1772@gmail.com'
app.config['MAIL_PASSWORD'] = 'aiuy awpu mfoi cyrf'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

# User model
class User(UserMixin, db.Document):
    username = db.StringField(required=True, unique=True)
    email = db.StringField(required=True, unique=True)
    password = db.StringField(required=True)
    image_file = db.StringField(default='default.jpg')
    created_at = db.DateTimeField(default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

# Post model
class Post(db.Document):
    title = db.StringField(required=True)
    date_posted = db.DateTimeField(default=datetime.datetime.utcnow)
    content = db.StringField(required=True)
    author = db.ReferenceField('User', reverse_delete_rule=db.CASCADE)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.objects.get(id=user_id)

# Route for displaying posts
@app.route('/posts')
def Posts():
    posts = Post.objects()
    return render_template('posts.html', posts=posts)

# Profile route (restricted to the logged-in user)
@app.route('/profile/<username>')
@login_required
def profile(username):
    # Ensure the logged-in user can only access their own profile
    if username != current_user.username:
        flash("You can only access your own profile.", "danger")
        return redirect(url_for('profile', username=current_user.username))  # Redirect to their own profile

    user = User.objects(username=username).first()
    posts = Post.objects(author=user)
    return render_template('profile.html', profile=user, posts=posts)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login_view():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.objects(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)  # Use Flask-Login to log in the user
            flash('Login successful!', 'success')
            return redirect(url_for('Posts'))
        else:
            flash("Invalid credentials", 'danger')
            return redirect(url_for('login_view'))
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout_view():
    logout_user()  # Use Flask-Login to log out the user
    flash('You are logged out.', 'info')
    return redirect(url_for('login_view'))

# Forgot password route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        user = User.objects(username=username).first()
        if not user:
            flash("User not found!", "error")
            return redirect(url_for('forgot_password'))
        
        otp = random.randint(1000, 9999)
        session['otp'] = otp

        msg = Message('Your OTP for Password Reset', 
                    sender='rakeshchowdary1772@gmail.com', 
                    recipients=[email])
        msg.body = f'Your OTP is: {otp}'
        mail.send(msg)

        flash('OTP has been sent to your email!', 'info')
        return render_template('forgot_password.html', is_otp=True)

    return render_template('forgot_password.html', forgot=True)

# OTP verification route
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp_input = request.form.get('otp')

        if 'otp' not in session:
            flash('No OTP found. Please request OTP again.', 'warning')
            return redirect(url_for('forgot_password'))

        if int(otp_input) == session['otp']:
            flash('OTP verified successfully!', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid OTP. Please try again', 'danger')
            return render_template('forgot_password.html', is_otp=True)

    return render_template('forgot_password.html', is_otp=True)

# Password reset route
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        
        user = User.objects.get(username=current_user.username)
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        user.save()

        session.pop('otp', None)  # Clear OTP from session after reset
        flash('Password reset successfully!', 'success')
        return redirect(url_for('login_view'))

    return render_template('forgot_password.html', reset=True)

# Register user route
@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        image_file = request.form.get('image_file') or 'default.jpg'

        existing_user = User.objects(__raw__={'$or': [{'username': username}, {'email': email}]}).first()

        if existing_user:
            flash("User already exists. Please choose a different username.", 'danger')
            return redirect(url_for('login_view'))
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, email=email, password=hashed_password, image_file=image_file)
            user.save()

            flash("Registration successful! Please log in.", 'success')
            return redirect(url_for('login_view'))
    
    return render_template('register_user.html')

# Create post route
@app.route('/create_post', methods=['POST', 'GET'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')

        post = Post(title=title, content=content, author=current_user._get_current_object())
        post.save()
        flash(f"Post '{title}' created successfully!", 'success')

        return redirect(url_for('Posts'))

    return render_template('create_post.html')

# Edit post route
@app.route('/edit_post/<id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = Post.objects.get(id=id)
    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')
        post.save()

        flash("Post updated successfully!", "success")
        return redirect(url_for('Posts'))

    return render_template('post_edit.html', post=post)

# Edit user route
@app.route('/edit_user/<id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    user = User.objects.get(id=id)
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        user.image_file = request.form.get('image_file') or 'default.jpg'
        user.save()

        flash("User updated successfully!", "success")
        return redirect(url_for('profile', username=user.username))

    return render_template('user_edit.html', user=user)



# Delete post route
@app.route('/delete_post/<post_id>', methods=['POST', 'GET'])
@login_required
def post_delete(post_id):
    post = Post.objects(id=post_id).first()
    if post:
        post.delete()
        flash("Post deleted successfully!", "success")
    else:
        flash("Post not found!", "danger")

    return redirect(url_for('Posts'))

if __name__ == "__main__":
    app.run(debug=True)
