from __future__ import division, unicode_literals, print_function

from flask import Flask,render_template,flash, redirect,url_for,session,logging,request,jsonify
from flask_sqlalchemy import SQLAlchemy

from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import os.path
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from models import create_post, get_posts

import copy
import json
import plac

from pathlib import Path
import spacy
from spacy.util import minibatch, compounding
import json
import sys
import textacy
import textacy.keyterms
from collections import defaultdict
import random
import os
import itertools

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/fahadkamraan/Downloads/flask-login-register-form-master/database.db'

db_path = os.path.join(os.path.dirname(__file__),'database.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri

CORS(app)
Bootstrap(app)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class user(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80))
	email = db.Column(db.String(120))
	password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

class LoginForm(FlaskForm):
	username = StringField('username', validators=[InputRequired(), Length(min=4,max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=8,max=80)])
	remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
	email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
	username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

@app.route("/")
def index():
	return render_template("index.html")

@app.route('/posts', methods=['GET', 'POST'])
def postlist():
	if request.method == 'GET':
		pass

	if request.method == 'POST':
		name = request.form.get('name')
		post = request.form.get('post')
		create_post(name, post)

	posts = get_posts()

	return render_template('index.html', posts=posts)

@app.route("/login",methods=["GET", "POST"])
def login():
	if request.method == "POST":
		uname = request.form["uname"]
		passw = request.form["passw"]

		login = user.query.filter_by(username=uname, password=passw).first()
		if login is not None:
			return redirect(url_for("index"))
	return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
	if request.method == "POST":
		uname = request.form['uname']
		mail = request.form['mail']
		passw = request.form['passw']

		register = user(username = uname, email = mail, password = passw)
		db.session.add(register)
		db.session.commit()

		return redirect(url_for("login"))
	return render_template("register.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
	form = RegisterForm()

	if form.validate_on_submit():
		hashed_password = generate_password_hash(form.password.data, method='sha256')
		# if User.query.filter_by(username=form.username.data).first() == form.username.data:
		#     flash("Username already exits!")
		# else:
		new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
		db.session.add(new_user)
		db.session.commit()

		return '<h1>New user has been created!</h1>'
		#return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

	return render_template('signup.html', form=form)

@app.route('/welcome')
@login_required
def welcome():
	return render_template('hello.html')


@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('login'))


"""
	The schedule planner takes in a JSON that contains the user's work 'Start
	time', and a list of 'Tasks', each of which comes with a 'Task' name and
	expected time 'Length' in minutes.
	IMPORTANT: ALL TASKS ARE LISTED IN DESCENDING ORDER OF IMPORTANCE!
	A break of variable length is required between two tasks.
	Breaks must be at least 5 minutes long.
	Any tasks longer than 2 hours can be split into two or more blocs, but
	each bloc can be chopped up to an hour at least.
	(e.g. a task with 4 hours length will be chopped into 4 blocs at most)
	All meal breaks are required to be an hour long.
	NOON and SUPPER are default values used for lunch break and dinner break
	if those values are not provided by the user.

	All time formats will take the following form:
	[Hour, Minute]
	(i.e. a list of two integers, first element indicating hour and second
	element indicating minute.)

	The scheduler returns a JSON containing a list of tasks, their start time
	and length, breaks included.
"""

@app.route('/schedule', methods=['POST'])
def get_schedule():
	json_data=[]

	f = request.get_json()
	#f = json.load(f1)
	start = f["Start time"].split(":") # [Hour, minute]
	tasks = f["Tasks"]

	for i in range(2):
		start[i] = int(start[i])

	"""Greedy Algorithm based lazy scheduler: Simply assign tasks in order of
	importance, with these rules:
	1. First meal break is always 3 hrs after start time. Margin of
	error += 30 min
	2. Second meal break is always 6 hrs after end of first meal break.
	Margin of error += 30 min
	3. Split any tasks greater than 2 hours into 2 or more blocs, but
	each bloc must be 60 minutes or greater.
	4. In case of a tie between different bloc splits, go with the one
	that uses slots most efficiently.
	5. 15 minute mandatory breaks between any blocs.
	"""

	modified_tasklist = []
	for item in tasks:
		new_taskitem = copy.deepcopy(item)
		if item["Length"] >= 120:
			divisors = []
			divisor = 1
			while item["Length"] / divisor >= 60:
				divisors.append(divisor)
				divisor += 1
			new_taskitem["divisors"] = divisors
		else:
			new_taskitem["divisors"] = [1]
		modified_tasklist.append(new_taskitem)

	slots = []
	last_time = 0
	Lunch_assigned = False
	Dinner_assigned = False
	lunchtime = 0
	dinnertime = 0

	for i in range(len(modified_tasklist)):
		item = modified_tasklist[i]
		if "Assigned" in item.keys():
			continue
		if not Lunch_assigned:
			# Morning schedule scenario
			if last_time + item["Length"] < 180:
				# Task length doesn't go over the 3 hour morning time
				# slot restriction.
				if item["Length"] < 120:
					# Task length is less than 2 hours = go ahead assign it.
					bloc = copy.deepcopy(item)
					bloc["Start"] = last_time
					slots.append(bloc)
					last_time += (bloc["Length"] + 15) # 15 min break.
					item["Assigned"] = "Yes"
				else: # item["Length"] < 180:
					# Task length is between 2 to 3 hours = split, then assign.

					# This is an edge case: Ideally the task would be
					# split into two blocs with a 15 minute break
					# in between them.
					di_bloc = copy.deepcopy(item)
					di_bloc["Length"] = int(item["Length"] / 2)
					di_bloc["Start"] = last_time
					slots.append(di_bloc)
					last_time += (di_bloc["Length"] + 15)
					di_bloc2 = copy.deepcopy(di_bloc)
					di_bloc2["Start"] = last_time
					slots.append(di_bloc2)
					last_time += (di_bloc2["Length"] + 15)
					item["Assigned"] = "Yes"
			else:
				# Task length goes over the remaining time slots in the
				# morning hours.
				if item["Length"] > 120:
					# Task length is greater than 2 hours = split, then assign.
					# Assign lunch hours in between.

					# First, check how much time is remaining in the morning slot.
					remainder = 180 - last_time
					if remainder > 60 and remainder < 120:
						# Remainder of time is greater than 60 but less than 120 =
						# split, then deal with the rest later.
						di_bloc = copy.deepcopy(item)
						remainder_block = copy.deepcopy(item)
						di_bloc["Length"] = 60
						remainder_block["Length"] = item["Length"] - 60
						di_bloc["Start"] = last_time
						slots.append(di_bloc)
						last_time += (di_bloc["Length"])

						lunch = {"Task": "Lunch", "Length": 60, "Start": last_time}
						slots.append(lunch)
						lunchtime = last_time
						last_time += 60 # 60 minute lunch break
						Lunch_assigned = True

						# Now we look at the remainder block.

						# Find the smallest divisor that results in each bloc
						# getting 120 minutes or less. Since a split has
						# already occurred, it could be 1, but depending on
						# length of task, divisor may be 2 or 3.

						divisor = 1
						while remainder_block["Length"] / divisor > 120:
							divisor += 1

						miniblocs = []
						for k in range(divisor):
							miniblocs.append(copy.deepcopy(remainder_block))
							miniblocs[k]["Length"] = int(remainder_block["Length"] / divisor)
							miniblocs[k]["Start"] = last_time
							slots.append(miniblocs[k])
							last_time += (miniblocs[k]["Length"] + 15)
						item["Assigned"] = "Yes"

					elif remainder >= 120:
						# Remainder of the time is greater than 2 hours =
						# 1. Find enough smaller tasks that can fit into
						# that timeframe, or
						# 2. Split the current task into enough blocs to
						# efficiently fill up the remaining timeframe, then
						# assign dinner.
						# Now the situation is a lot trickier since we have
						# a downtime of more than 2 hours and a task that
						# exceeds that length.

						target_not_found = False

						while remainder not in range(-30, 60) and not target_not_found:
							assign_this = None

							for j in range(i + 1, len(modified_tasklist)):
								if modified_tasklist[j]["Length"] < remainder and "Assigned" not in modified_tasklist[j]:
									assign_this = modified_tasklist[j]
									assign_this["Assigned"] = "Yes"
									break

							if assign_this is not None:
								bloc = copy.deepcopy(assign_this)
								bloc["Start"] = last_time
								slots.append(bloc)
								last_time += (bloc["Length"] + 15)
								remainder -= (bloc["Length"] + 15)
							else:
								target_not_found = True

						if target_not_found:
							# This means we weren't able to find any smaller
							# tasks to fill in the gap with. Split the current
							# task into smaller pieces so that they fit into
							# the gap as much as they can.

							di_bloc = copy.deepcopy(item)
							remainder_block = copy.deepcopy(item)
							di_bloc["Length"] = remainder
							remainder_block["Length"] = item["Length"] - remainder

							# This is done by reverse-dividing the remaining
							# time in a similar fashion as done to blocks of
							# tasks.
							divisor = 1
							while remainder / divisor > 120:
								divisor += 1

							miniblocs = []
							for k in range(divisor):
								miniblocs.append(copy.deepcopy(di_bloc))
								miniblocs[k]["Length"] = int(remainder / divisor)
								miniblocs[k]["Start"] = last_time
								slots.append(miniblocs[k])
								last_time += (miniblocs[k]["Length"] + 15)

							last_time -= 15
							lunch = {"Task": "Lunch", "Length": 60, "Start": last_time}
							slots.append(lunch)
							lunchtime = last_time
							last_time += 60 # 60 minute lunch break
							Lunch_assigned = True

							divisor = 1
							while remainder_block["Length"] / divisor > 120:
								divisor += 1

							miniblocs = []
							for k in range(divisor):
								miniblocs.append(copy.deepcopy(remainder_block))
								miniblocs[k]["Length"] = int(remainder_block["Length"] / divisor)
								miniblocs[k]["Start"] = last_time
								slots.append(miniblocs[k])
								last_time += (miniblocs[k]["Length"] + 15)
							item["Assigned"] = "Yes"
						else:
							# Gap has been filled with tasks. Now assign lunch
							# and then assign the current task we're looking at.
							last_time -= 15 # no need for break between task and lunch
							lunch = {"Task": "Lunch", "Length": 60, "Start": last_time}
							slots.append(lunch)
							lunchtime = last_time
							last_time += 60 # 60 minute lunch break
							Lunch_assigned = True

							# Now we have to assign the current task we are looking at.
							# Find the smallest divisor that results in each bloc
							# getting 120 minutes or less. The divisor could be
							# 2, but depending on length of task, divisor may
							# be 3 or 4.

							divisor = 2
							while item["Length"] / divisor > 120:
								divisor += 1

							miniblocs = []
							for k in range(divisor):
								miniblocs.append(copy.deepcopy(item))
								miniblocs[k]["Length"] = int(item["Length"] / divisor)
								miniblocs[k]["Start"] = last_time
								slots.append(miniblocs[k])
								last_time += (miniblocs[k]["Length"] + 15)
							item["Assigned"] = "Yes"

					else:
						# Remainder of time is less than 60 = look for
						# a different task that can fit in here, then
						# assign the current task immediately after lunch.
						assign_this = None

						for j in range(i + 1, len(modified_tasklist)):
							if modified_tasklist[j]["Length"] < remainder and "Assigned" not in modified_tasklist[j]:
								assign_this = modified_tasklist[j]
								assign_this["Assigned"] = "Yes"
								break

						if assign_this is not None:
							bloc = copy.deepcopy(assign_this)
							bloc["Start"] = last_time
							slots.append(bloc)
							last_time += (bloc["Length"] + 15)

						# If none of the tasks can be assigned, then we
						# simply go through with a lunch break assignment.
						last_time -= 15 # no need for break between task and lunch
						lunch = {"Task": "Lunch", "Length": 60, "Start": last_time}
						slots.append(lunch)
						lunchtime = last_time
						last_time += 60 # 60 minute lunch break
						Lunch_assigned = True

						# Now we have to assign the current task we
						# are looking at
						# Find the smallest divisor that results in each bloc
						# getting 120 minutes or less. The divisor could be
						# 2, but depending on length of task, divisor may
						# be 3 or 4.

						divisor = 2
						while item["Length"] / divisor > 120:
							divisor += 1

						miniblocs = []
						for k in range(divisor):
							miniblocs.append(copy.deepcopy(item))
							miniblocs[k]["Length"] = int(item["Length"] / divisor)
							miniblocs[k]["Start"] = last_time
							slots.append(miniblocs[k])
							last_time += (miniblocs[k]["Length"] + 15)
						item["Assigned"] = "Yes"

				else:
					# Task length is less than 2 hours = look for
					# a different task that can fit in here, then
					# assign the current task immediately after lunch.
					assign_this = None

					for j in range(i + 1, len(modified_tasklist)):
						if modified_tasklist[j]["Length"] < remainder and "Assigned" not in modified_tasklist[j]:
							assign_this = modified_tasklist[j]
							assign_this["Assigned"] = "Yes"
							break

					if assign_this is not None:
						bloc = copy.deepcopy(assign_this)
						bloc["Start"] = last_time
						slots.append(bloc)
						last_time += (bloc["Length"] + 15)

					# If none of the tasks can be assigned, then we
					# simply go through with a lunch break assignment.
					last_time -= 15 # no need for break between task and lunch
					lunch = {"Task": "Lunch", "Length": 60, "Start": last_time}
					slots.append(lunch)
					lunchtime = last_time
					last_time += 60 # 60 minute lunch break
					Lunch_assigned = True

					# Now we have to assign the current task we
					# are looking at. Since it is less than 2 hours,
					# we can simply go ahead and assign it immediately.
					bloc = copy.deepcopy(item)
					bloc["Start"] = last_time
					slots.append(bloc)
					last_time += (bloc["Length"] + 15) # 15 min break.
					item["Assigned"] = "Yes"

			if not Lunch_assigned and last_time in range(165, 226):
				# Sum of all tasks assigned so far since beginning is
				# roughly around 3 hours and task assigned just now
				# didn't overshoot the 3 hour slot time.
				last_time -= 15 # no need for break between task and lunch
				lunch = {"Task": "Lunch", "Length": 60, "Start": last_time}
				slots.append(lunch)
				lunchtime = last_time
				last_time += 60 # 60 minute lunch break
				Lunch_assigned = True
		elif not Dinner_assigned:
			# Afternoon schedule scenario
			# Probably the hardest part because of the larger slot length
			# and still need to observe meal break regulations.
			if last_time + item["Length"] < 360:
				# Task length doesn't go over the 6 hour afternoon time
				# slot restriction.
				if item["Length"] < 120:
					# Task length is less than 2 hours = go ahead assign it.
					bloc = copy.deepcopy(item)
					bloc["Start"] = last_time
					slots.append(bloc)
					last_time += (bloc["Length"] + 15) # 15 min break.
					item["Assigned"] = "Yes"
				else: # item["Length"] < 360:
					# Task length is between 2 to 6 hours = split, then assign.

					# Find the smallest divisor that results in each bloc
					# getting 120 minutes or less. It will usually be 2, but
					# depending on length of task, divisor may be 3 or 4.

					divisor = 2
					while item["Length"] / divisor > 120:
						divisor += 1

					miniblocs = []
					for j in range(divisor):
						miniblocs.append(copy.deepcopy(item))
						miniblocs[j]["Length"] = int(item["Length"] / divisor)
						miniblocs[j]["Start"] = last_time
						slots.append(miniblocs[j])
						last_time += (miniblocs[j]["Length"] + 15)
					item["Assigned"] = "Yes"
			else:
				# Task length goes over the remaining time slots in the
				# afternoon hours.
				if item["Length"] > 120:
					# Task length is greater than 2 hours = split, then assign.
					# Assign dinner hours in between.

					# First, check how much time is remaining in the afternoon slot.
					remainder = 360 - last_time
					if remainder > 60 and remainder < 120:
						# Remainder of time is greater than 60 but
						# less than 120 = split,
						# then deal with the rest later.
						di_bloc = copy.deepcopy(item)
						remainder_block = copy.deepcopy(item)
						di_bloc["Length"] = 60
						remainder_block["Length"] = item["Length"] - 60
						di_bloc["Start"] = last_time
						slots.append(di_bloc)
						last_time += (di_bloc["Length"])

						dinner = {"Task": "Dinner", "Length": 60, "Start": last_time}
						slots.append(dinner)
						dinnertime = last_time
						last_time += 60 # 60 minute lunch break
						Dinner_assigned = True

						# Now we look at the remainder block.

						# Find the smallest divisor that results in each bloc
						# getting 120 minutes or less. Since a split has
						# already occurred, it could be 1, but depending on
						# length of task, divisor may be 2 or 3.

						divisor = 1
						while remainder_block["Length"] / divisor > 120:
							divisor += 1

						miniblocs = []
						for k in range(divisor):
							miniblocs.append(copy.deepcopy(remainder_block))
							miniblocs[k]["Length"] = int(remainder_block["Length"] / divisor)
							miniblocs[k]["Start"] = last_time
							slots.append(miniblocs[k])
							last_time += (miniblocs[k]["Length"] + 15)
						item["Assigned"] = "Yes"
					elif remainder >= 120:
						# Remainder of the time is greater than 2 hours =
						# 1. Find enough smaller tasks that can fit into
						# that timeframe, or
						# 2. Split the current task into enough blocs to
						# efficiently fill up the remaining timeframe, then
						# assign dinner.
						# Now the situation is a lot trickier since we have
						# a downtime of more than 2 hours and a task that
						# exceeds that length.

						target_not_found = False

						while remainder not in range(-30, 60) and not target_not_found:
							assign_this = None

							for j in range(i + 1, len(modified_tasklist)):
								if modified_tasklist[j]["Length"] < remainder and "Assigned" not in modified_tasklist[j]:
									assign_this = modified_tasklist[j]
									assign_this["Assigned"] = "Yes"
									break

							if assign_this is not None:
								bloc = copy.deepcopy(assign_this)
								bloc["Start"] = last_time
								slots.append(bloc)
								last_time += (bloc["Length"] + 15)
								remainder -= (bloc["Length"] + 15)
							else:
								target_not_found = True

						if target_not_found:
							# This means we weren't able to find any smaller
							# tasks to fill in the gap with. Split the current
							# task into smaller pieces so that they fit into
							# the gap as much as they can.

							di_bloc = copy.deepcopy(item)
							remainder_block = copy.deepcopy(item)
							di_bloc["Length"] = remainder
							remainder_block["Length"] = item["Length"] - remainder

							# This is done by reverse-dividing the remaining
							# time in a similar fashion as done to blocks of
							# tasks.
							divisor = 1
							while remainder / divisor > 120:
								divisor += 1

							miniblocs = []
							for k in range(divisor):
								miniblocs.append(copy.deepcopy(di_bloc))
								miniblocs[k]["Length"] = int(remainder / divisor)
								miniblocs[k]["Start"] = last_time
								slots.append(miniblocs[k])
								last_time += (miniblocs[k]["Length"] + 15)

							last_time -= 15
							dinner = {"Task": "Dinner", "Length": 60, "Start": last_time}
							slots.append(dinner)
							dinnertime = last_time
							last_time += 60 # 60 minute lunch break
							Dinner_assigned = True

							divisor = 1
							while remainder_block["Length"] / divisor > 120:
								divisor += 1

							miniblocs = []
							for k in range(divisor):
								miniblocs.append(copy.deepcopy(remainder_block))
								miniblocs[k]["Length"] = int(remainder_block["Length"] / divisor)
								miniblocs[k]["Start"] = last_time
								slots.append(miniblocs[k])
								last_time += (miniblocs[k]["Length"] + 15)
							item["Assigned"] = "Yes"

						else:
							# Gap has been filled with tasks. Now assign dinner
							# and then assign the current task we're looking at.
							last_time -= 15 # no need for break between task and dinner
							dinner = {"Task": "Dinner", "Length": 60, "Start": last_time}
							slots.append(dinner)
							dinnertime = last_time
							last_time += 60 # 60 minute dinner break
							Dinner_assigned = True

							# Now we have to assign the current task we are looking at.
							# Find the smallest divisor that results in each bloc
							# getting 120 minutes or less. The divisor could be
							# 2, but depending on length of task, divisor may
							# be 3 or 4.

							divisor = 2
							while item["Length"] / divisor > 120:
								divisor += 1

							miniblocs = []
							for k in range(divisor):
								miniblocs.append(copy.deepcopy(item))
								miniblocs[k]["Length"] = int(item["Length"] / divisor)
								miniblocs[k]["Start"] = last_time
								slots.append(miniblocs[k])
								last_time += (miniblocs[k]["Length"] + 15)
							item["Assigned"] = "Yes"

					else:
						# Remainder of time is less than 60 = look for
						# a different task that can fit in here, then
						# assign the current task immediately after dinner.
						assign_this = None

						for j in range(i + 1, len(modified_tasklist)):
							if modified_tasklist[j]["Length"] < remainder and "Assigned" not in modified_tasklist[j]:
								assign_this = modified_tasklist[j]
								assign_this["Assigned"] = "Yes"
								break

						if assign_this is not None:
							bloc = copy.deepcopy(assign_this)
							bloc["Start"] = last_time
							slots.append(bloc)
							last_time += (bloc["Length"] + 15)

						# If none of the tasks can be assigned, then we
						# simply go through with a dinner break assignment.
						last_time -= 15 # no need for break between task and dinner
						dinner = {"Task": "Dinner", "Length": 60, "Start": last_time}
						slots.append(dinner)
						dinnertime = last_time
						last_time += 60 # 60 minute dinner break
						Dinner_assigned = True

						# Now we have to assign the current task we are looking at.
						# Find the smallest divisor that results in each bloc
						# getting 120 minutes or less. The divisor could be
						# 2, but depending on length of task, divisor may
						# be 3 or 4.

						divisor = 2
						while item["Length"] / divisor > 120:
							divisor += 1

						miniblocs = []
						for k in range(divisor):
							miniblocs.append(copy.deepcopy(item))
							miniblocs[k]["Length"] = int(item["Length"] / divisor)
							miniblocs[k]["Start"] = last_time
							slots.append(miniblocs[k])
							last_time += (miniblocs[k]["Length"] + 15)
						item["Assigned"] = "Yes"

				else:
					# Task length is less than 2 hours = look for
					# a different task that can fit in here, then
					# assign the current task immediately after dinner.
					assign_this = None

					for j in range(i + 1, len(modified_tasklist)):
						if modified_tasklist[j]["Length"] < remainder and "Assigned" not in modified_tasklist[j]:
							assign_this = modified_tasklist[j]
							assign_this["Assigned"] = "Yes"
							break

					if assign_this is not None:
						bloc = copy.deepcopy(assign_this)
						bloc["Start"] = last_time
						slots.append(bloc)
						last_time += (bloc["Length"] + 15)

					# If none of the tasks can be assigned, then we
					# simply go through with a dinner break assignment.
					last_time -= 15 # no need for break between task and dinner
					dinner = {"Task": "Dinner", "Length": 60, "Start": last_time}
					slots.append(dinner)
					dinnertime = last_time
					last_time += 60 # 60 minute dinner break
					Dinner_assigned = True

					# Now we have to assign the current task we
					# are looking at. Since it is less than 2 hours,
					# we can simply go ahead and assign it immediately.
					bloc = copy.deepcopy(item)
					bloc["Start"] = last_time
					slots.append(bloc)
					last_time += (bloc["Length"] + 15) # 15 min break.
					item["Assigned"] = "Yes"

			if not Dinner_assigned and last_time in range(lunchtime + 60 + 345, lunchtime + 60 + 406):
				# Sum of all tasks assigned so far since end of lunch is
				# roughly around 6 hours and task assigned just now
				# didn't overshoot the 6 hour slot time.
				last_time -= 15 # no need for break between task and dinner
				dinner = {"Task": "Dinner", "Length": 60, "Start": last_time}
				slots.append(dinner)
				dinnertime = last_time
				last_time += 60 # 60 minute lunch break
				Dinner_assigned = True
		else:
			# Evening schedule scenario
			# This is the most lax part of scheduling since there are
			# no meal break restrictions to look out for. Just assign
			# remaining tasks, split where necessary, and add breaks
			# in between
			if item["Length"] < 120:
				# Task length is less than 2 hours = go ahead assign it.
				bloc = copy.deepcopy(item)
				bloc["Start"] = last_time
				slots.append(bloc)
				last_time += (bloc["Length"] + 15) # 15 min break.
				item["Assigned"] = "Yes"
			else: # item["Length"] >= 120:
				# Task length is 2 hours or more = split, then assign.
				# Find the smallest divisor that results in each bloc
				# getting 120 minutes or less. It will usually be 2, but
				# depending on length of task, divisor may be 3 or 4.

				divisor = 2
				while item["Length"] / divisor > 120:
					divisor += 1

				miniblocs = []
				for j in range(divisor):
					miniblocs.append(copy.deepcopy(item))
					miniblocs[j]["Length"] = int(item["Length"] / divisor)
					miniblocs[j]["Start"] = last_time
					slots.append(miniblocs[j])
					last_time += (miniblocs[j]["Length"] + 15)
				item["Assigned"] = "Yes"

	"""
		The polishing stage
		This is where we polish the data. Sometimes due to the divisor resulting
		in odd numbers, the schedule may look awkward (e.g. starting time of
		2:48 pm or 11:34 am). Here the algorithm traverses through all assigned
		slots to check for these awkward data points. This is also the stage
		where any last minute schedule switches can occur due to awkwardly
		placed meal breaks. Last but not least, an edge case where dinner meals
		are skipped will be handled here by reversing the lunch/dinner split
		algorithm.
	"""
	#print(slots)
	# First, check if the meal breaks aren't too close to each other.
	# The arbitrary threshold I use here is 6 hours, with an error margin
	# of 60 minutes give or take.
	#print(dinnertime - (lunchtime + 60))
	breakloop = False
	while (dinnertime - (lunchtime + 60)) not in range(300, 421) and not breakloop:
		# Shift dinner time later until it reaches the above threshold.
		for i in range(len(slots)):
			if i == len(slots) - 1:
				breakloop = True
				break
			if slots[i]["Task"] == "Dinner" and i != len(slots) - 1:
				temp = slots[i]
				slots[i] = slots[i + 1]
				slots[i + 1] = temp

				temp2 = slots[i]["Start"]
				slots[i]["Start"] = slots[i + 1]["Start"] + 15
				slots[i + 1]["Start"] = slots[i]["Start"] + slots[i]["Length"]
				dinnertime = slots[i + 1]["Start"]
				#print(dinnertime - (lunchtime + 60))
				if (dinnertime - (lunchtime + 60)) in range(300, 421):
					breakloop = True
					break

	# Next, we modify any start/end times that point to awkward times.
	for i in range(len(slots)):
		item = slots[i]
		rem = (item["Start"] + item["Length"]) % 5
		if rem != 0:
			if rem < 2:
				item["Length"] -= rem
				for j in range(i + 1, len(slots)):
					slots[j]["Start"] -= rem
			else:
				item["Length"] += 5 - rem
				for j in range(i + 1, len(slots)):
					slots[j]["Start"] += 5 - rem

	# Last but not least, check if the dinner meal has been skipped.
	if not Dinner_assigned:
		dinnertime = slots[-1]["Start"] - 15 + slots[-1]["Length"]
		slots.append({"Task": "Dinner", "Length": 60, "Start": dinnertime})
		breakloop = False
		while (dinnertime - (lunchtime + 60)) not in range(300, 421) and not breakloop:
			# Shift dinner time later until it reaches the above threshold.
			for i in range(len(slots)-1,-1,-1):
				if i == 0:
					breakloop = True
					break
				if slots[i]["Task"] == "Dinner" and i != 0:
					temp = slots[i - 1]
					slots[i - 1] = slots[i]
					slots[i] = temp

					temp2 = slots[i - 1]["Start"]
					slots[i - 1]["Start"] = slots[i]["Start"] - 15
					slots[i]["Start"] = slots[i - 1]["Start"] + 60
					dinnertime = slots[i - 1]["Start"]
					#print(dinnertime - (lunchtime + 60))
					if (dinnertime - (lunchtime + 60)) in range(300, 420):
						breakloop = True
						break

	# Now we process slots before returning it as a proper json.
	json_data = []
	for i in range(len(slots)):
		item = slots[i]
		item_hour = item["Length"] // 60
		item_min = item["Length"] % 60
		new_item = {}
		new_item["Task"] = item["Task"]
		if start[1] < 10:
			new_item["Start"] = str(start[0]) + ":0" + str(start[1])
		else:
			new_item["Start"] = str(start[0]) + ":" + str(start[1])
		item_end_hour = start[0] + item_hour
		item_end_min = start[1] + item_min
		if item_end_min >= 60:
			temp = item_end_min
			item_end_min = item_end_min % 60
			item_end_hour += (temp // 60)
		if item_end_min < 10:
			new_item["End"] = str(item_end_hour) + ":0" + str(item_end_min)
		else:
			new_item["End"] = str(item_end_hour) + ":" + str(item_end_min)
		json_data.append(new_item)
		print(new_item["Task"] + " begins at " + new_item["Start"] + " and ends at " + new_item["End"])
		start[0] = item_end_hour
		start[1] = item_end_min
		if i != len(slots)-1 and (slots[i+1]["Task"] != "Lunch" and slots[i+1]["Task"] != "Dinner") and (slots[i]["Task"] != "Lunch" and slots[i]["Task"] != "Dinner"):
			start[1] += 15
			if start[1] >= 60:
				temp = start[1]
				start[1] = start[1] % 60
				start[0] += (temp // 60)

	return jsonify(json_data)

@app.route('/getkeywords', methods=['GET'])
def get_keywords():
	mess = get_posts()

	#with open("messagelist.json", 'r') as f1:
	#	datastore = json.load(f1)
	#	for item in datastore:
	#		mess.append(item["results"])

	clustering_results = clustering_analysis(input=mess)

	result1 = clustering_results.split(",")
	final_json = {"keywords":result1}

	return jsonify(final_json)


"""
	Below are helper functions for the clustering analysis to work.
"""

def clustering_analysis(input=None, algorithm="s", n_key_float=0.75, n_grams="1,2,3,4",
		cutoff=10, threshold=0.5):
	if algorithm != "t" and algorithm != "s":
		return("Specify an algorithm! (t)extrank or (s)grank")

	if input is None:
		return("Specify input file with -i")

	alldata = []

	for curline in input:
		alldata.append(curline)

	# Preprocess data by removing garbage keywords
	alldata = clean_data(alldata)

	# the cummulative tally of common keywords
	word_keyterm_cummula = defaultdict(lambda: 0)
	# the mapping of journals to the common keywords
	word_keyterm_journals = defaultdict(lambda: [])

	en = textacy.load_spacy_lang("en_core_web_sm", disable=("parser",))
	for item in alldata:
		msgid = item.split(' ')[0]
		curline = item.replace(msgid, '').strip()
		curdoc = textacy.make_spacy_doc(curline.lower(), lang=en)
		curdoc_ranks = []
		if algorithm == "t":
			if n_key_float > 0.0 and n_key_float < 1.0:
				curdoc_ranks = textacy.keyterms.textrank(curdoc,
					normalize="lemma", n_keyterms=n_key_float)
			else:
				curdoc_ranks = textacy.keyterms.textrank(curdoc,
					normalize="lemma", n_keyterms=n_key)
		elif algorithm == "s":
			ngram_str = set(n_grams.split(','))
			ngram = []
			for gram in ngram_str:
				ngram.append(int(gram))
			curdoc_ranks = textacy.keyterms.sgrank(curdoc,
				window_width=1500, ngrams=ngram, normalize="lower",
				n_keyterms=n_key_float)

		for word in curdoc_ranks:
			word_keyterm_cummula[word[0]] += 1
			word_keyterm_journals[word[0]].append((msgid, word[1]))
			if len(word_keyterm_journals[word[0]]) > 10:
				newlist = []
				min_tuple = word_keyterm_journals[word[0]][0]
				for tuple in word_keyterm_journals[word[0]]:
					if tuple[1] < min_tuple[1]:
						min_tuple = tuple
				for tuple in word_keyterm_journals[word[0]]:
					if tuple[0] != min_tuple[0]:
						newlist.append(tuple)
				word_keyterm_journals[word[0]] = newlist

	word_keyterm_cummula_sorted = sorted(word_keyterm_cummula.items(),
		key=lambda val: val[1], reverse=True)

	quint = 0
	quint_printout = ""
	for entry in word_keyterm_cummula_sorted[:cutoff]:
		quint_printout += entry[0] + ","
		quint += 1
	quint_printout = quint_printout[:-1]
	print(quint_printout)
	return quint_printout


"""
	Preprocessing function that removes excessive punctuations, any floating
	punctuations, any file extensions, and unneccessary entities.
"""

def clean_data(journal_list):
	nlp = spacy.load('en_core_web_sm')  # make sure to use larger model!

	fine_data = []
	# Delete any occurrences of these but keep the words attached to them.
	garbage_punc = ['...', '....', '.....', '///', '////', '/////', '---',
		'----', '-----']
	# Remove any files with these extensions
	file_exts = [".html", "[/url", ".xxx", ".jpg", ".jpeg", ".png", ".gif",
		".txt", ".doc", ".docx", ".pdf"]
	# Look for any words which contain these X's as substrings, remove them.
	xs = ['xxx', 'xxxx', 'xxxxx']
	# Delete any occurrences of these if they occur as a single token
	punctuations = ['!', '?', '_', '/', '-', '+', '=', '>', '|', '[', ']',
		'{', '}', '(', ')', ',', '#', "\"", "\'"]

	for curline in journal_list:
		# Separate the journal ID from the message, then remove all non-ascii
		# characters
		msgid = curline.split(' ')[0]
		curline = curline.replace(msgid, '').strip()
		curline = remove_non_ascii(curline).strip()

		# Get rid of gibberish - remove any excessive punctuations.
		for garb in garbage_punc:
			curline = curline.replace(garb, '')

		# Tokenize the sentence to further prune the sentences.
		doc = nlp(curline)
		strtok = ""
		for token in doc:
			if token.ent_type_ not in remove_these_entities:
				strtok += token.text + " "

		# Remove all punctuation marks.
		for char in strtok:
			if char in punctuations:
				if strtok[0:2] == char + ' ':
					strtok = strtok[2:]
				elif strtok[-2:] == ' ' + char:
					strtok = strtok[:-2]
				else:
					strtok = strtok.replace(' ' + char + ' ', ' ')

		stringtoanalyze = strtok.strip()
		removal_dump = []

		"""
			Go through the string and prune the following:

			1. Any non-English words.
			2. Any word greater than 20 characters in length.
			3. Any Base64 encryptions and file names.
			4. Any words with lots of 'x' in it.
		"""
		for word in stringtoanalyze.split():
			if not isEnglish(word):
				removal_dump.append(word)
				continue
			if len(word) > 20:
				removal_dump.append(word)
				continue
			if word[-4:] in file_exts or word[-5:] in file_exts or \
					word[-2:] == "==":
				removal_dump.append(word)
				continue
			wordlw = word.lower()
			if "xxxx" in wordlw or "xxx" in wordlw or wordlw[:4] == "xxxx" or \
					wordlw[-4:] == "xxxx" or wordlw[:3] == "xxx" or \
					wordlw[-3:] == "xxx":
				removal_dump.append(word)
				continue
			for exes in xs:
				if exes in wordlw:
					removal_dump.append(word)

		for rem in removal_dump:
			if stringtoanalyze == rem:
				stringtoanalyze = ""
			elif stringtoanalyze[:len(rem)] == rem:
				stringtoanalyze = stringtoanalyze[len(rem):]
			elif stringtoanalyze[(-1 * len(rem)):] == rem:
				stringtoanalyze = stringtoanalyze[:(-1 * len(rem))]
			else:
				stringtoanalyze = stringtoanalyze.replace(' ' + rem + ' ', ' ')

		# If all the pruning results in a nonempty string of length greater
		# than 1, it is safe to use for clustering.
		stringtoanalyze = stringtoanalyze.strip()
		if len(nlp(stringtoanalyze)) > 1:
			fine_data.append(msgid + ' ' + stringtoanalyze + '\n')

	print("Done with cleaning data.")

	return fine_data


"""
	Functions to remove any non-English words and emojis from journals for
	preprocessing purposes.
"""
def remove_non_ascii(s):
	for char in s:
		if len(char.encode('utf-8')) > 3:
			s = s.replace(char, '')
	return s


def isEnglish(s):
	try:
		s.encode(encoding='utf-8').decode('ascii')
	except UnicodeDecodeError:
		return False
	else:
		return True

if __name__ == "__main__":
	db.create_all()
	app.run(debug=True)
