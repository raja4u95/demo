======================================================
P6 Web Services Java Demo Client
======================================================

===================
Running
===================
1) Double click on the p6wsdemo.jar file.  This should pop up a window where you can enter the following fields:

User Name: The database User Name
Password: The database User Password
Project Id: An Id (String) for the project that will be created when this demo is run.
Host: The hostname/ip address of the machine on which the P6 Web Services is deployed.
Port: The port number of the server.

2) Clicking on the 'Test' Button does the following:

a)Checks if a project with the given id exits in the database, and deletes it if found.
b)Reads the root EPS.
d)Creates a project with the given Id, under the EPS retrieved in the previous step.
e)Add three activities under the newly created project.


===================
Building
===================

If you will be editing the source file, you can build it with Apache Ant:

1) Run the ant command with the target 'jar':

	> ant jar

This will create the jar file under the current directory.

===================
Encryption
===================

We have not included an example keystore for security purposes.
However, it is quite simple to create your own with 'keytool', bundled with java.

Running just 'keytool' will give you a list of options available to you.

For our purposes, we need a public/private key pair, and a digital certificate.

The command '-genkeypair' is, therefore, what we want.

Example:

> keytool -genkeypair -keystore keystore.jks -keypass keypass -storepass storepass -alias wsalias -keyalg RSA

It will then ask you a series of questions pertaining to the digital certificate we are creating.

Example:

> What is your first and last name? [Unknown]:

When it asks if this information is correct, answer yes.

Refer to the admin guide on how to setup your P6WS install to use encryption and this keystore.

Then, correctly supply the parameters to the keystore you just created in this demo.