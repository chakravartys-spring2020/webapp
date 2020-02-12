# Assignment 4 Updated Fork

![CSYE 6250 Cloud Engineering and Network Structure | Spring 2020 [BOS-2-TR]](https://assets.postman.com/postman-docs/ramen-app.png)


## Prerequisites for building and deploying application locally

Open a Terminal and Change Directory to Home

$ cd ~

Install Postgresql


```console
foo@bar:~$ sudo apt update
foo@bar:~$ sudo apt install postgresql postgresql-contrib
```

Switch from default linux to  default database user
```console
foo@bar:~$ sudo -u postgres psql
```

Create your sample database with the following SQL queries
```console
foo@bar:~$ CREATE TABLE users ( id PRIMARY KEY UNIQUE, first_name VARCHAR (50) NOT NULL, last_name VARCHAR (50) NOT NULL, email_address VARCHAR (50) UNIQUE NOT NULL, password VARCHAR (50) NOT NULL, account_created TIMESTAMP, account_updated TIMESTAMP );

foo@bar:~$ CREATE TABLE bills (
    column_name1 col_type (field_length) column_constraints,
    column_name2 col_type (field_length),
    column_name3 col_type (field_length)
);
```

Open your favourite terminal and install PGAdmin for a nice GUI to monitor your local database

```console
foo@bar:~$ wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
 sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt/ `lsb_release -cs`-pgdg main" >> /etc/apt/sources.list.d/pgdg.list'

 foo@bar:~$ sudo apt install pgadmin4 pgadmin4-apache2 -y
```

Finally run PGAdmin on its default port 5050
```console
foo@bar:~$ sudo python3 /usr/share/pgadmin4/web/pgAdmin4.py
```

Fire up any web browser and navigate to:
<b> http://127.0.0.1:5050/browser/# </b>

Finally to run the REST Server and API, open up a new Terminal and punch in the following environment variables:

```console
foo@bar:~$ export DATABASE_URL=postgresql://postgres:postgres@127.0.0.1/postgres
foo@bar:~$ export FLASK_ENV=development
```

Now you are ready to fire up the REST API server with:
```console
foo@bar:~$ python3 run.py
```

All that remains is installing Postman via Snap, to interface with and send through crafted HTTP requests to your REST API:

```console
foo@bar:~$ snap install postman
```

Voila...You are up and running my friend! May the force be with you...

# Build and Deploy instructions for web application
