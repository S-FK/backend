from flask import Blueprint
from flask import flash
from flask import g
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from werkzeug.exceptions import abort

from coolspace.auth import login_required
from coolspace.db import get_db

# The following import statements are necessary for the clustering algorithm to work.
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
# End of import statements for clustering analysis.


bp = Blueprint("post", __name__)


@bp.route("/")
def index():
    """Show all the posts, most recent first."""
    db = get_db()
    posts = db.execute(
        "SELECT p.id, title, body, created, author_id, username"
        " FROM post p JOIN user u ON p.author_id = u.id"
        " ORDER BY created DESC"
    ).fetchall()
    return render_template("post/index.html", posts=posts)


def get_post(id, check_author=True):
    """Get a post and its author by id.

    Checks that the id exists and optionally that the current user is
    the author.

    :param id: id of post to get
    :param check_author: require the current user to be the author
    :return: the post with author information
    :raise 404: if a post with the given id doesn't exist
    :raise 403: if the current user isn't the author
    """
    post = (
        get_db()
        .execute(
            "SELECT p.id, title, body, created, author_id, username"
            " FROM post p JOIN user u ON p.author_id = u.id"
            " WHERE p.id = ?",
            (id,),
        )
        .fetchone()
    )

    if post is None:
        abort(404, "Post id {0} doesn't exist.".format(id))

    if check_author and post["author_id"] != g.user["id"]:
        abort(403)

    return post


@bp.route("/create", methods=("GET", "POST"))
@login_required
def create():
    """Create a new post for the current user."""
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        error = None

        if not title:
            error = "Title is required."

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                "INSERT INTO post (title, body, author_id) VALUES (?, ?, ?)",
                (title, body, g.user["id"]),
            )
            db.commit()
            return redirect(url_for("post.index"))

    return render_template("post/create.html")


@bp.route("/<int:id>/update", methods=("GET", "POST"))
@login_required
def update(id):
    """Update a post if the current user is the author."""
    post = get_post(id)

    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        error = None

        if not title:
            error = "Title is required."

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                "UPDATE post SET title = ?, body = ? WHERE id = ?", (title, body, id)
            )
            db.commit()
            return redirect(url_for("post.index"))

    return render_template("post/update.html", post=post)


@bp.route("/<int:id>/delete", methods=("POST",))
@login_required
def delete(id):
    """Delete a post.

    Ensures that the post exists and that the logged in user is the
    author of the post.
    """
    get_post(id)
    db = get_db()
    db.execute("DELETE FROM post WHERE id = ?", (id,))
    db.commit()
    return redirect(url_for("post.index"))


@bp.route('/getkeywords', methods=('GET',))
def get_keywords():
    mess_sql = get_db().execute("SELECT * FROM post").fetchall()
    mess = []
    for item in mess_sql:
        mess.append({"message": "{} {}".format(str(item[0]), item[4])})

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

	alldata = []

	for curline in input:
		alldata.append(curline["message"])

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
    #print(quint_printout)
    return quint_printout
