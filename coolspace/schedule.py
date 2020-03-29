import copy
import json

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

    :param schedule_json: A JSON object containing the user's input, which
	consists of a list of tasks with their names and expected duration.
    :return: List of dictionaries that contain tasks divided and/or arranged
	out with their start times and end times in string format. Can be
	jsonified.
"""

def get_schedule(schedule_json):
	#json_data=[]

	#f = request.get_json()
	f = json.load(schedule_json)
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

	return json_data
