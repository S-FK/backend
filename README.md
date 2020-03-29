# CoolSpace Backend

## Steps to install

Once you clone the repository create a virtual environment and activate it.

    $python3 -m venv venv
    $. venv/bin/activate

Install CoolSpace

    $pip install -e .

Once installed check it with the following command

    $pip list

Run

    $ export FLASK_APP=coolspace
    $ export FLASK_ENV=development
    $ flask init-db
    $ flask run

Open http://127.0.0.1:5000 in a browser

and that's it.



