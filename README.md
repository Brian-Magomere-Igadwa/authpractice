To initialize db run 
```bash 
./scripts/init_db.sh 
```


We are following test-driven-development strictly. 
Tasks:
- [ ]  Write a unit test for a healthcheck endpoint
- [ ]  Implement a simple get healthcheck endpoint to test initial set up
- [ ]  Implement auth module with :
    - login + unit test
    - sign up + unit test
    - delete + unit test
    - update user profile + unit test
- [ ]  Write integration tests for the db and verify that storage , updates and deletion works as expected.
- [ ]  Dockerize the application and have the database run as a docker container too.
- [ ]  Persist the user in a relational database(postgress), just name, password, date-of-birth, country.
- [ ]  Do stress testing to the application, take note of bottlenecks e.g does too many people(could be single person sending multiple signup or sign in requests) signing up at once conducting sign ins, does that cause the server to be out of service? if that's the case fix that.

Email verification is beyond the scope of this task.