# Django-Webapp-Example

The above is the result of six months of on-again off-again work a couple years back, as I was looking to productize a collection of growth hacks I'd put together.

This Django app in particular is best suited for a suite of many small applications, for example as an internal tools / CRUD platform.

It is batteries-included, it is opinionated, and it is not guarenteed to work perfectly.¹ That said, you are here and reading this, so maybe poke around?

It is built to work with the following stack (but does not need any of them per se):
* Heroku - IaaS
* Postgres - Database
* Celery + Redis - Queuing + Async
* Github - Versioning + Deploy
* Pandas - File I/O + Analysis
* Tastypie - API provisioning
* Email/SMTP - Native + Gmail
* Rollbar - Error Reporting
* New Relic - Application Performance Management
* Native Django - Auth + Permissions
* Custom - IP / User Agent Rotation
* Custom - Logging + Pager Duty
* Custom  - Rate limiting + Monitoring

🚨 Dependabot says there are 4 vulnerabilities due to out of date libs. I am leaving them that way to ensure stability. I recommend you upgrade them once you have it working.

¹ in particular the Celery / Redis functionality has some problems around maxing the Worker CPU and hanging until timeout that I never resolved
