# Story app, by Félix Robb


import os
import re
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_argon2 import Argon2
from flask_migrate import Migrate
from sqlalchemy import func, or_
from datetime import datetime, timezone
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, FileField, validators, PasswordField, BooleanField, SelectField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stories.db'
app.config['SECRET_KEY'] = "knkdjnkjnjdjdj"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Custom secure filename function
def custom_secure_filename(filename):
    # Replace spaces with underscores and remove special characters
    filename = re.sub(r'[^\w.]+', '_', filename)
    return filename

csrf = CSRFProtect(app)
csrf.init_app(app)
db = SQLAlchemy(app)
argon2 = Argon2(app)  
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)


#Classes

#User class
# db models

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(100)) 
    privacy_setting = db.Column(db.String(20), default='public')
    theme = db.Column(db.String(20), default='light')  # Example: 'light' or 'dark'
    language = db.Column(db.String(10), default='en')  # Example: 'en' for English
    bio = db.Column(db.String(255))
    stories = db.relationship('Story', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    followers = db.relationship('Follow', foreign_keys='Follow.followed_id', backref='followed', lazy='dynamic')
    followed = db.relationship('Follow', foreign_keys='Follow.follower_id', backref='follower', lazy='dynamic')
    notifications = db.relationship('Notification', backref='user', lazy=True)
    profile_pic = db.Column(db.String(100), default='default.jpg')
    def set_password(self, password):
        self.password = password
        self.password_hash = argon2.generate_password_hash(password)

    def check_password(self, password):
        return argon2.check_password_hash(self.password_hash, password)

    def is_following(self, user):
        return self.followed.filter_by(followed_id=user.id).first() is not None

    def get_user_stories(self):
        return Story.query.filter_by(author=self).all()

    def get_followers(self):
        return self.followers.all()
        
        
# Story class
class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    synopsis = db.Column(db.String(200))
    content = db.Column(db.Text, nullable=False)
    tags = db.Column(db.String(100))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    versions = db.relationship('Version', backref='story', lazy=True)
    comments = db.relationship('Comment', backref='story', lazy=True)
    
    
    
# Edit proposals
class EditProposal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    story = db.relationship('Story', backref='edit_proposals', lazy=True)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'declined'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('edit_proposals', lazy=True))
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    author_approval = db.Column(db.Boolean, default=False)

    
    
 # Version  
class Version(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(20))
    content = db.Column(db.Text, nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)


# Comment
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)


# Follow
class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# Notifications
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

        
# Flask forms

# Login
class LoginForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    submit = SubmitField('Login')


 # Create story      
class CreateStoryForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    synopsis = StringField('Synopsis', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    tags = StringField('Tags')
    submit = SubmitField('Create Story') 


# Edit story
class EditForm(FlaskForm):
            edit = TextAreaField('Edit', validators=[DataRequired()])
            submit = SubmitField('Submit Edit')    
            

# Edit profile
class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    bio = TextAreaField('Bio')
    profile_pic = FileField('Profile Picture')
    submit = SubmitField('Save Changes')


# Comment
class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[DataRequired()])
    submit_comment = SubmitField('Submit Comment')
    
    
# Privacy settings
class PrivacySettingsForm(FlaskForm):
    privacy_setting = SelectField('Privacy Setting', choices=[('public', 'Public'), ('private', 'Private')])
    submit = SubmitField('Save Privacy Settings')


# Account settings

class AccountSettingsForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')
 
       
# Notifications preferences

class NotificationPreferencesForm(FlaskForm):
    story_updates = BooleanField('Receive Story Updates')
    comments = BooleanField('Receive Comments Notifications')
    followers = BooleanField('Receive Followers Notifications')
    submit = SubmitField('Save Preferences')
    

# Search
class SearchForm(FlaskForm):
    search_query = StringField('Search', render_kw={"placeholder": "Enter your search query"})
    submit = SubmitField('Search')


# Routes

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))
    return None


# Entry Page
@app.route('/entry', methods=['GET'])
def entry_page():
    return render_template('entry_page.html')
    
    
# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Replace with your actual login form class

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html', form=form)  # Pass the form to the template


# Logout
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    registration_form = RegistrationForm()  # Assuming you have a RegistrationForm class

    if request.method == 'POST' and registration_form.validate_on_submit():
        username = registration_form.username.data
        password = registration_form.password.data
        confirm_password = registration_form.confirm_password.data

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
        else:
            new_user = User(username=username)
            new_user.set_password(password)  
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html', form=registration_form)
    
    
# Edit profile
@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_profile(user_id):
    user = User.query.get(user_id)
    if user != current_user:
        abort(403)
    if user:
        form = EditProfileForm()

        if form.validate_on_submit():
            user.username = form.username.data
            user.bio = form.bio.data

            if form.profile_pic.data:
                filename = custom_secure_filename(form.profile_pic.data.filename)
                form.profile_pic.data.save(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], filename))
                user.profile_pic = filename

            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('user_page', user_id=user_id))

        elif request.method == 'GET':
            form.username.data = user.username
            form.bio.data = user.bio

        return render_template('edit_profile.html', form=form, user=user)



    
# index/Feed
@app.route('/')
@login_required
def index():
    subquery = db.session.query(
        Version.story_id,
        func.max(Version.date).label('max_date')
    ).group_by(Version.story_id).subquery()

    stories = (
        Story.query
        .join(subquery, Story.id == subquery.c.story_id)
        .order_by(subquery.c.max_date.desc())
        .all()
    )

    return render_template('feed.html', stories=stories)


# create story
@app.route('/create_story', methods=['GET', 'POST'])
@login_required
def create_story():
    form = CreateStoryForm()

    if form.validate_on_submit():
        title = form.title.data
        synopsis = form.synopsis.data
        content = form.content.data
        tags = form.tags.data

        # Create a new story
        new_story = Story(
            title=title,
            synopsis=synopsis,
            content=content,
            tags=tags,
            author=current_user
        )

        # Create an initial version for the story
        initial_version = Version(
            date=datetime.now(timezone.utc).strftime('%Y-%m-%d'),
            content=content,
            story=new_story
        )

        db.session.add(new_story)
        db.session.add(initial_version)
        db.session.commit()

        flash('Story created successfully!', 'success')
        return redirect(url_for('index')) # to view story

    return render_template('create_story.html', form=form)


# View story
@app.route('/story/<int:story_id>')
@login_required
def view_story(story_id):
    story = Story.query.get(story_id)
    versions = Version.query.filter_by(story=story).all()
    edit_proposals = EditProposal.query.filter_by(story=story, status='pending').all()

    if story:
        form = CommentForm()
        return render_template('view_story.html', story=story, versions=versions, edit_proposals=edit_proposals, form=form)
    else:
        return "Story not found", 404
        
        
# Edit story
@app.route('/story/<int:story_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_story(story_id):
    story = Story.query.get(story_id)
    if story:
        form = EditForm()

        if request.method == 'POST':
            new_edit = request.form.get('edit')
            if new_edit:
                # Create an edit proposal
                edit_proposal = EditProposal(content=new_edit, user=current_user, story=story)
                db.session.add(edit_proposal)
                db.session.commit()

                # Notify the author
                notification_content = f"New edit proposal for your story '{story.title}'"
                new_notification = Notification(content=notification_content, user=story.author)
                db.session.add(new_notification)
                db.session.commit()

                flash('Edit proposal submitted. Waiting for author approval.', 'info')
                return redirect(url_for('view_story', story_id=story_id))
            else:
                flash('Content cannot be empty.', 'error')

        return render_template('edit_story.html', story=story, form=form)
    else:
        abort(404)

# Edit proposal acept/decline
@app.route('/story/edit_proposal/<int:proposal_id>/<string:action>', methods=['POST'])
@login_required
def handle_edit_proposal(proposal_id, action):
    proposal = EditProposal.query.get(proposal_id)

    if proposal and proposal.story.author == current_user:
        if action == 'accept':
            # Apply the accepted edit to the story
            proposal.story.content = proposal.content
            proposal.status = 'accepted'
            proposal.author_approval = True
            db.session.commit()
            flash('Edit proposal accepted!', 'success')
        elif action == 'decline':
            # Mark the edit proposal as declined
            proposal.status = 'declined'
            db.session.commit()
            flash('Edit proposal declined.', 'info')
        else:
            flash('Invalid action.', 'error')
    else:
        flash('Permission denied or edit proposal not found.', 'error')

    return redirect(url_for('view_story', story_id=proposal.story.id))
    
# Proposals
@app.route('/story/<int:story_id>/proposals', methods=['GET'])
@login_required
def view_edit_proposals(story_id):
    story = Story.query.get(story_id)
    if story and story.author == current_user:
        # Retrieve edit proposals for the story
        proposals = EditProposal.query.filter_by(story=story).options(joinedload('user')).all()
        return render_template('view_edit_proposals.html', story=story, proposals=proposals)
    else:
        abort(403)


# Comment
@app.route('/story/<int:story_id>/comment', methods=['POST'])
@login_required
def add_comment(story_id):
    story = Story.query.get(story_id)
    if story and request.method == 'POST':
        comment_content = request.form.get('comment')
        if comment_content:
            new_comment = Comment(content=comment_content, author=current_user, story=story)
            db.session.add(new_comment)
            db.session.commit()
            flash('Comment added successfully!', 'success')
        else:
            flash('Comment content cannot be empty.', 'error')

    return redirect(url_for('view_story', story_id=story_id))


# Follow
@app.route('/user/<int:user_id>/follow', methods=['POST'])
@login_required
def follow_user(user_id):
    user_to_follow = User.query.get(user_id)
    if user_to_follow and user_to_follow != current_user:
        if not current_user.is_following(user_to_follow):
            follow = Follow(follower=current_user, followed=user_to_follow)
            db.session.add(follow)
            db.session.commit()
            flash(f'You are now following {user_to_follow.username}!', 'success')
        else:
            flash('You are already following this user.', 'info')
    else:
        flash('User not found or cannot follow yourself.', 'error')
    return redirect(url_for('index'))




# User page
@app.route('/user/<int:user_id>')
@login_required
def user_page(user_id):
    user = User.query.get(user_id)
    if user:
        user_stories = user.get_user_stories()
        followers = user.get_followers()

        # Retrieve a list of users that the current user does not follow but has a connection with
        suggested_users = User.query.filter(User.id != current_user.id, ~current_user.followers.filter_by(follower_id=User.id).exists()).all()

        # Check if the current user is viewing their own page or another user's page
        if user == current_user:
            is_own_page = True
        else:
            is_own_page = False

        return render_template('user_page.html', user=user, user_stories=user_stories, followers=followers, suggested_users=suggested_users, is_own_page=is_own_page)
    else:
        return "User not found", 404


# Search
@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    form = SearchForm()

    if form.validate_on_submit():
        query = form.search_query.data

        # Search for stories with titles or tags containing the query
        story_results = Story.query.filter(or_(Story.title.ilike(f'%{query}%'), Story.tags.ilike(f'%{query}%'))).all()

        # Search for users with usernames containing the query
        user_results = User.query.filter(User.username.ilike(f'%{query}%')).all()

        return render_template('search_results.html', query=query, story_results=story_results,
                               user_results=user_results)

    return render_template('search.html', form=form)


# Notifications
@app.route('/notifications')
@login_required
def notifications():
    user_notifications = (
    Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all())
    return render_template('notifications.html', notifications=user_notifications)


# Settings
@app.route('/user/settings', methods=['GET'])
@login_required
def user_settings():
    return render_template('settings.html', user=current_user)
    
    
# General Settings
@app.route('/user/settings/general', methods=['GET', 'POST'])
@login_required
def general_settings():
    if request.method == 'POST':
        # Handle saving general settings logic
        user = current_user
        user.language = request.form.get('language')
        user.theme = request.form.get('theme')
        db.session.commit()
        flash('General settings saved successfully!', 'success')
        return redirect(url_for('general_settings'))
    return render_template('general_settings.html', user=current_user)
    
    
    # Account Settings
@app.route('/user/settings/account', methods=['GET', 'POST'])
@login_required
def account_settings():
    if request.method == 'POST':
        # Handle saving account settings logic
        user = current_user
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Check if the current password is correct
        if user.check_password(current_password):
            # Check if the new password matches the confirmation
            if new_password == confirm_password:
                user.set_password(new_password)
                db.session.commit()
                flash('Account settings saved successfully!', 'success')
                return redirect(url_for('account_settings'))
            else:
                flash('New password and confirmation do not match.', 'error')
        else:
            flash('Current password is incorrect.', 'error')

    return render_template('account_settings.html', user=current_user)
    
    # Notification Settings
@app.route('/user/settings/notifications', methods=['GET', 'POST'])
@login_required
def notification_settings():
    if request.method == 'POST':
        # Handle saving notification settings logic
        user = current_user
        user.story_updates = 'story_updates' in request.form
        user.comments = 'comments' in request.form
        user.followers = 'followers' in request.form
        db.session.commit()
        flash('Notification settings saved successfully!', 'success')
        return redirect(url_for('notification_settings'))
    return render_template('notification_settings.html', user=current_user)
    
# Privacy Settings
@app.route('/user/settings/privacy', methods=['GET', 'POST'])
@login_required
def privacy_settings():
    if request.method == 'POST':
        # Handle saving privacy settings logic
        user = current_user
        user.privacy_setting = request.form.get('privacy_setting')
        db.session.commit()
        flash('Privacy settings saved successfully!', 'success')
        return redirect(url_for('privacy_settings'))
    return render_template('privacy_settings.html', user=current_user)

        
        
# Run app
if __name__ == "__main__":
    app.run(host='0.0.0.0')