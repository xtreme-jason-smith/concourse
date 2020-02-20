> **If you are running a production environment, it might be wise to wait on a
future stable release before upgrading to this major version.**

This release bumps us to v6.0 for good reason: it's the first time we've
changed how Concourse decides on the inputs for your jobs.

A whole new algorithm for deciding job inputs has been implemented, which
performs much better for large-scale Concourse instances with a ton of versions
and builds. This algorithm works in a fundamentally different way, and in some
situations will yield different results than the previous algorithm. Read on
for more information!

Even though this release has been tested at scale and in all kinds of ways, we
want to be more cautious with this release than usual, because we've pretty
much replaced the "brain" of Concourse. If there are any bugs, given the nature
of the beast, this could result in undesireable behavior in production
environments (such as shipping the wrong version).

**IMPORTANT**: Please expect and prepare for some downtime when upgrading to
v6.0. On our large scale deployments, we have seen 10-20 minutes of downtime in
order to migrate the database but it will vary depending on the size of your
deployment.

#### <sub><sup><a name="3602" href="#3602">:link:</a></sup></sub> feature, breaking

* > **vito**: Hey Clara, want to write the release note for the new algorithm?  \
  > **clarafu**: yeah sure whatever  \
  > **vito**: Try to spice it up a bit, it's not really a sexy feature.  \
  > **clarafu**: you got it boss

  Has this ever happened to you? "My Concourse is getting slower and slower
  even though I'm not adding any new pipelines!" "The web nodes are always
  under such heavy load!" "My database is constantly overloaded!"

  Well have no fear, because Algorithm V3 is here! #3602

  <p align="center">
    <img width="460" height="300" src="http://localhost:8000/images/wow.gif">
  </p>

  You might be wondering, what is the algorithm and why do I care about it? YOU FOOL! The algorithm is the heart and soul of Concourse! The algorithm is what determines the inputs for every newly created build in your pipeline. (If you want to read more about how the algorithm works, check out the [scheduler docs][scheduler-docs].)

  The main goal of the new algorithm is to increase scalibility and efficiency. The old algorithm used to load up all the resource versions, build inputs and build outputs into memory then use brute-force to figure out what the next inputs would be. This method worked well enough in most cases, but once you have a huge deployment with thousands or even millions of versions or build inputs/outputs it would start to put a lot of strain on the `web` and `db` niodes.

  With the new algorithm, it will only query for the specific data that it needs at the time it needs it. This dramatically reduces resource utilization of both the `web` and `db` nodes.

  You can think of the difference in the context of going to the grocery store to buy a specific brand of bacon. The old algorithm would've gone to the grocery store and bought all the different brands of bacon that it had ever purchased. It would then bring home all the bacon and then figure out which brand it actually needed. It's possible that it didn't need to use the majority of the bacon, and most of it goes to waste. Think about how much money would be spent doing this and how inefficient it is! By comparison, the new algorithm would first figure out which brand of bacon it needs then go to the grocery store and grab that brand. It might need to take multiple trips to the store if it figures out that the brand isn't the one it wants, but in the end, it'll still be more.

  If you still are not convinced with the bacon metaphor, here is a few metrics to show the difference between the old and new algorithm. These metrics were taken off our large scale environment and the first metric is showing the database CPU usage. The database was completely pegged before the upgrade and after the upgrade, it has been sitting at an average of 65% CPU usage.

  ![Database CPU Usage](http://localhost:8000/images/new-vs-old-db-cpu.png)

  This next metrics is showing database data transfer, where the left side of the graph shows the metric for the old algorithm and the right side shows the data transfer for the new algorithm after the upgrade.

  ![Database Data Transfer](http://localhost:8000/images/new-vs-old-data-transfer.png)

  There are two key breaking change with the behaviour of this new algorithm. The first breaking change is that for inputs with passed constraints, rather than using resource versions to determine the versions considered to be inputs, it will use the passed constraints job's build inputs. It might make more sense with an example.

  ![Difference in behavior between old and new algorithm](http://localhost:8000/images/old-vs-new-algorithm.png)

  Let's say we have a pipeline that has one resource that is used as an input to two jobs and one of the job is a passed constraint to the other. This resource has three versions and the first job that directly depends on that resource has ran twice producing two builds, each with different resource versions; v3 and v1. The difference between the old and new algorithm comes in when we take a look at what version will be used for a new build of the second job.

  In the old algorithm, it would use v3 as the input version to the second job (as shown by the orange line). This is because the old algorithm would use the resource versions to figure out what version will be next, and since there are no version constraints, it grabs the latest. And as long as that latest version has passed through the first job, it satisfies the passed constraint.

  Now, in the new algorithm it will use v1 as the input version (as shown by the green line). The new algorithm figures out the input versions for inputs with passed constraints using the build inputs of the passed constraint job. This means that if the latest build of the first job used an old version of the resource, that will be the version used to trigger off the downstream jobs.

  The second breaking change is a difference between the rules behind whether or not a new build will be scheduled for a set of versions. What that means is after the algorithm determines a set of input versions that will be used for the next build of this job, the scheduler will take that set of versions and figure out whether or not a new build should be scheduled.

  In the old algorithm, the scheduler would only schedule a new build if any of the versions for the [triggerable](https://concourse-ci.org/get-step.html#get-step-trigger) resources has never been run before by **any past builds** of the job. In other words, if the algorithm runs and computes an input version has been used to run a build 2 months ago, the scheduler would not schedule a new build because the version has been used by a past build already.

  In the new algorithm, the scheduler will schedule a new build if any of the versions for the [triggerable](https://concourse-ci.org/get-step.html#get-step-trigger) resources has never run by the **previous build** of the job. What this means is if the algorithm runs and computes an input version, the scheduler will create a new build as long as that version is different than the previous build's version for that same input. Even if that version has been used by a build 2 months ago, the scheduler will schedule a new build as long as it has not been used by the previous build.

  With this new behavior of the algorithm, if there are any input versions that are different than the previous build, it will trigger a new build. This can be undesirable for some users with the way many of you are using pinning in order to run a build with old versions, because it would result in the situation where input versions that have previously run in an old build being triggered again unexpectedly. Here's an example to describe the kind of situation that can happen:

  Let's say you have a job that takes a resource as an input. It currently has two builds, build 1 has ran with version `v1` of the resource and build 2 has ran with `v2`.

  ![Example job with two builds](http://localhost:8000/images/new-pinning-behavior-1.png)

  For the old algorithm, if I pin the input to an older version I would need to manually trigger a new build in order to produce a build using the pinned version. This is because there already existed a build using the pinned version `v1` so the old algorithm determined that a new build was not needed to be scheduled. And then if I unpin the version, nothing happens and build 3 is still the latest build.

  ![Pinning with old algorithm](http://localhost:8000/images/new-pinning-behavior-2.png)

  If I pin the input to an older version using the new algorithm, a new build is produced without a manual trigger because the pinned version `v1` is not equivalent to the version of the previous build `v2`.

  ![Pinning with the new algorithm](http://localhost:8000/images/new-pinning-behavior-3.png)

  Now if I unpin the version, another build would be triggered using the latest version. This is because after unpinning the resource, the input version for the next build becomes the latest version `v2` which is not equal to the version `v1` used by the previous build.

  ![Unpin with new algorithm](http://localhost:8000/images/new-pinning-behavior-4.png)

  This is to allow the current state of the builds to always reflect the current state of the versions. That being said, this behavior can be undesirable if I don't want another build to be created with the latest version everytime I pin and unpin a resource version because all I really care about is rerunning the job using an old version. This is where the next big feature of 6.0 comes in, the next feature outlined in these release notes will be the solution to this problem!

  One thing to note is that with this huge restructuring of a major component of Concourse, there ought to be a lot of concern over the data migration that might happen along with it. This was something that was taken into huge consideration and rather than having one giant migration to move over all the build and input versions into a new format that is useable by the new algorithm, we decided to incrementally migrate it on demand. The algorithm will migrate data over to the new format only if it needs to, which means a less risky upgrade migration and possibly less data that needs to be moved over to this new format because of old data that is no longer used is not needed to be copied.

* Along with the new algorithm, we wanted to improve the transparency of showing why inputs are failing to find a proper set of versions for a build. In the preparation view of a pending build, if the algorithm is failing to find an appropriate set of versions it will give an error message for the inputs that it is failing on.

[scheduler-docs]: https://TODO

#### <sub><sup><a name="3704" href="#3704">:link:</a></sup></sub> feature, breaking

* LIDAR is now on by default! In fact, not only is it on by default, it is now THE ONLY OPTION. The old and busted 'Radar' resource checking component has been removed. The `--enable-lidar` flag will no longer be recognized. #3704

#### <sub><sup><a name="413" href="#413">:link:</a></sup></sub> feature

* This next feature is one that has been asked for since the beginning of time. Build rerunning! #413 We finally did it, even though it is only the first iteration.

  You are finally able to rerun an old build with the same set of input versions without using the pinning trick. When you rerun a build, it will create a new build using the name of the original build with the rerun number appended to it. You can rerun a build either through the rerun button on the build page or through the fly command `fly rerun-build`. The rerun button is located at the top right corner of the build page, to the left of the button for manually triggering a new build.

  The rerun build will be ordered with the original build, so that it isn't treated as the "latest" build of the job (unless it is a rerun of the latest build) but rather as another run of the original build. This means that if you rerun an old build, the status of the build will not show up in the pipeline page for the status of the job. This is because the status of the job represents the current state of the job, which a rerun of an old build is not treated as the current state.

  Build rerunning fixes a key breaking change in the new algorithm. If you pin a resource to an old version and trigger a new build, once you unpin the resource there will be another new build scheduled using the latest version in order to respect the current state of the versions. This might be undesirable for the users that only wants to run a build using an old version without affecting the latest state of the builds. If you retrigger a build, it will only create a rerun of an old build and that does not affect the latest state of the job in regards to it's builds.

  This is currently a first pass at build retriggering, as it only supports retriggering builds that have the same set of inputs as the *current state of the job config*. What this means is that if you have an old build that only had two inputs and you have recently added a new input (so now you have a total of 3 inputs to this job), if you try to retrigger that old build that only used two inputs it will fail. This is because this first pass at build retriggering uses the latest state of the job config but runs it with the exact versions of the build that is being retriggered. That being said, there are future plans to have retriggering execute an exact rerun of a build including all the versions and job config that it used to run with originally. If you are interested in tracking the progress for the second pass at retriggering, the project epic is called [Build Lifecycle View](https://project.concourse-ci.org/projects/MDc6UHJvamVjdDM3NjI5MTk=).

#### <sub><sup><a name="4717" href="#4717">:link:</a></sup></sub> feature

* Along with the big changes to the algorithm, we also redesigned the build scheduler to hopefully help remove some unnecessary work. #4717 The old per pipeline scheduler is now transformed into one giant scheduler with one per ATC. This giant scheduler will now be responsible for scheduling all the jobs within the deployment.

  The exciting new feature is that now, it will only schedule jobs that "need to be scheduled". This means that if there is nothing happening, for example on the weekends when there are no new versions of resources or nobody triggering new builds, the scheduler will not run. This will help reduce unnecessary load to your web or database nodes. If you want to read more about what defines a job to "need to be scheduled", you can read the docs [here](_____) that describe exactly the cases that the scheduler will run for.

  As a small proof of the performance enhancement this feature adds, these are two metrics of the before and after of an upgrade to this new scheduling logic. There are two graphs, the one on the left labelled `Scheduling By Job` is a heat map that shows the time taken for each job to schedule. The graph on the right labelled `Total Time Scheduling Jobs + Loading Algorithm DB` shows the total time taken to schedule all jobs plus the total time taken to load the Algorithm database. Loading the algorithm database was used by the old algorithm in order to load up all the build inputs and outputs and resource versions into memory from the database. On the left side of both graphs, it shows the time taken for the old scheduler and on the right side it shows the time taken for the new scheduler.

  ![Old vs new Build Scheduling](https://concourse-ci.org/images/old-vs-new-build-scheduling.png)

  If we analyze the `Scheduling By Job` heap map, you will notice that the old scheduler consistently had a ton of jobs to schedule while the new scheduler has less jobs to schedule but might take longer to schedule each job. The new scheduler only schedules the jobs that need to be scheduled, which will result in less jobs scheduling overall but the time taken to schedule each job could possibly be slower than the old scheduler because of the difference in the new and old algorithm. The new algorithm needs to run small queries in order to find the next version for a build which is slower if you compare that to the old algorithm that already had all the versions loaded up into memory and only needs to number crunch. A contributing factor to this graph result is that it does not include the time it took to load up the versions DB for the old algorithm.

  Now if we look at the `Total Time Scheduling Jobs + Loading Algorithm DB` graph, we can see a big difference between the old and new scheduler. The total time the old scheduler took to schedule all the jobs plus the time it took to load up the versions DB is drastically higher than the total time taken to schedule all jobs by the new scheduler. This is because even though the time taken to schedule each job might be slightly slower in the new scheduler, because it no longer schedules all jobs every 10 seconds it results in a lot of time and CPU saved from doing unnecessary work.

  This is a new feature that is also risky in some ways. Because the "failure" case here would be that the scheduler does not run when it is expected to run and you would see no builds being scheduled. In order to help de-risk this failure case, we added a new fly command `fly schedule-job` that will kick off the scheduler if this ever happens.

#### <sub><sup><a name="4973" href="#4973">:link:</a></sup></sub> feature

* @evanchaoli introduced another new step type in #4973: the [`load_var` step](https://concourse-ci.org/steps.html#load-var-step)! This step can be used to load a value from a file at runtime and set it in a ["local var source"](https://concourse-ci.org/vars.html#local-vars) so that later steps in the build may pass the value to fields like `params`.

  With this primitive, resource type authors will no longer have to implement two ways to parameterize themselves (i.e. `tag` and `tag_file`). Resource types can now implement simpler interfaces which expect values to be set directly, and Concourse can handle the busywork of reading the value from a file.

  This feature, like `set_pipeline` step, is considered **experimental** until its corresponding RFC, [RFC #27](https://github.com/concourse/rfcs/pull/27) is resolved. The step will helpfully remind you of this fact by printing a warning on every single use.

#### <sub><sup><a name="4616" href="#4616">:link:</a></sup></sub> feature

* In #4614, @julia-pu implemented a way for `put` steps to automatically determine the artifacts they need, by configuring [`inputs: detect`](https://concourse-ci.org/steps.html#schema.step.put-step.inputs). With `detect`, the step will walk over its `params` and look for paths that correspond to artifact names in the build plan (e.g. `tag: foo/bar` or just `repository: foo`). When it comes time to run, only those named artifacts will be given to the step, which can avoid wasting a lot of time transferring artifacts the step doesn't even need.

  This feature may become the default in the future if it turns out to be useful and safe enough in practice. Try it out!

#### <sub><sup><a name="5118" href="#5118">:link:</a></sup></sub> feature

* #5118 implements infinite scroll and lazy rendering to the dashboard, which should greatly improve performance on installations with a ton of pipelines configured. The initial page load can still be quite laggy, but interacting with the page afterwards now performs a lot better. We'll keep chipping away at this problem and may have larger changes in store for the future.

#### <sub><sup><a name="5149" href="#5149">:link:</a></sup></sub> fix

* In #5149, @evanchaoli implemented an optimization which should lower the resource checking load on some instances: instead of checking *all* resources, only resources which are actually used as inputs will be checked.

#### <sub><sup><a name="5014" href="#5014">:link:</a></sup></sub> fix

* We fixed a bug where users that have upgraded from Concourse v5.6.0 to v5.8.0 with lidar enabled, they might experience a resource never being able to check because it is failing to create a check step. #5014

#### <sub><sup><a name="4065" href="#4065">:link:</a></sup></sub> fix

* Builds could get stuck in pending state for jobs that are set to run serially. If a build is scheduled but not yet started and the ATC restarts, the next time the build is picked up it will get stuck in pending state. This is because the ATC sees the job is set to run in serial and there is already a build being scheduled, so it will not continue to start that scheduled build. This bug is now fixed with the new release, where builds will never be stuck in a scheduled state because of it's serial configuration. #4065

#### <sub><sup><a name="5158" href="#5158">:link:</a></sup></sub> fix

* If you had lidar enabled, there is the possibility of some duplicate work being done in order to create checks for custom resource types. This happens when there are multiple resources that use the same custom resource type, they will all try to create a check for that custom type. In the end, there will only be one check that happens but the work involved with creating the check is duplicated. This bug was fixed so that there will be only one attempt to create a check for a custom resource type even if there are multiple resources that use it. #5158

#### <sub><sup><a name="5157" href="#5157">:link:</a></sup></sub> fix

* The length of time to keep around the history of a resource check was defaulted to 6 hours, but we discovered that this default might cause slowness for large deployments because of the number of checks that are kept around. The default is changed to 1 minute, and it is left up to the user to configure it higher if they would like to keep around the history of checks for longer. #5157

#### <sub><sup><a name="5023" href="#5023">:link:</a></sup></sub> fix

* The dashboard page refreshes its data every 5 seconds. Until now, it was possible (especially for admin users) for the dashboard to initiate an ever-growing number of API calls, unnecessarily consuming browser, network and API resources. Now the dashboard will not initiate a request for more data until the previous request finishes. #5023

#### <sub><sup><a name="4862" href="#4862">:link:</a></sup></sub> feature

* Whenever the dashboard page is loaded, it would decrypt and unmarshal all the job configs for all the teams that the user has access to. This would be slow if there are a ton of jobs. We made a change that would result in the dashboard no longer needing to decrypt or unmarshal the config of jobs, which will help speed up the loading of the dashboard page. #4862

#### <sub><sup><a name="4406" href="#4406">:link:</a></sup></sub> feature

* We added a `--team-name` flag to a few fly commands which will allow users that have access to multiple teams to not need to login to each team in order to run a command against it! #4406

#### <sub><sup><a name="5075" href="#5075">:link:</a></sup></sub> fix

* Previously, the build tracker would unconditionally fire off a goroutine for each in-flight build (which then locks and short-circuits if the build is already tracked). We changed it so that the build tracker will only do so if we don't have a goroutine for it already. #5075

#### <sub><sup><a name="2724" href="#2724">:link:</a></sup></sub> fix

* We fixed a bug for job that have any type of serial groups set (`serial: true`, `serial_groups` or `max_in_flight`). Whenever a build for that job would be scheduled and we check for if the job has hit max in flight, it would unnecessarily recreate all the serial groups in the database. #2724

#### <sub><sup><a name="5039" href="#5039">:link:</a></sup></sub> fix

* The scheduler will separate the scheduling of rerun and regular builds (builds created by the scheduler and manually triggered builds) so that in situations where a rerun build is failing to schedule, maybe the input versions are not found, it will not block the scheduler from scheduling regular builds. #5039

#### <sub><sup><a name="4876" href="#4876">:link:</a></sup></sub> feature

* You can now easily enable or disable a resource version from the comfort of your command line using the new fly commands `fly enable-resource-version` and `fly disable-resource-version`, thanks to @stigtermichiel! #4876

#### <sub><sup><a name="5038" href="#5038">:link:</a></sup></sub> fix

* We fixed a bug where the existence of missing volumes that had child volumes referencing it was causing garbage collecting all missing volumes to fail. Missing volumes are any volumes that exists in the database but not on the worker. #5038

#### <sub><sup><a name="5100" href="#5100">:link:</a></sup></sub> fix

* The ResourceTypeCheckingInterval is not longer respected because of the removal of `radar` in this release with `lidar` becoming the default resource checker. Thanks to @evanchaoli for removed the unused flag `--resource-type-checking-interval`! #5100

#### <sub><sup><a name="4986" href="#4986">:link:</a></sup></sub> fix

* The link for the helm chart in the concourse github repo README was fixed thanks to @danielhelfand! #4986

#### <sub><sup><a name="4976" href="#4976">:link:</a></sup></sub> feature

* Include job label in build duration metrics exported to Prometheus. #4976

#### <sub><sup><a name="5093" href="#5093">:link:</a></sup></sub> fix

* The database will now use a version hash to look up resource caches in order to speed up any queries that reference resource caches. This will help speed up the resource caches garbage collection. #5093

#### <sub><sup><a name="5127" href="#5127">:link:</a></sup></sub> fix

* If you have `lidar` enabled, we fixed a bug where pinning an old version of a mock resource would cause it to become the latest version. #5127

#### <sub><sup><a name="5159" href="#5159">:link:</a></sup></sub> fix

* Explicitly whitelisted all traffic for concourse containers in order to allow outbound connections for containers on Windows. Thanks to @aemengo! #5159

#### <sub><sup><a name="5043" href="#5043">:link:</a></sup></sub> feature

* Add experimental support for exposing traces to [Jaeger] or [Stackdriver].

With this feature enabled (via `--tracing-(jaeger|stackdriver)-*` variables in
`concourse web`), the `web` node starts recording traces that represent the
various steps that a build goes through, sending them to the configured trace
collector. #5043

As this feature is being built using [OpenTelemetry], expect to have support for
other systems soon.

[OpenTelemetry]: https://opentelemetry.io/
[Jaeger]: https://www.jaegertracing.io/
[Stackdriver]: https://cloud.google.com/trace/

#### <sub><sup><a name="4092" href="#4092">:link:</a></sup></sub> feature

* @joshzarrabi added the `--all` flag to the `fly pause-pipeline` and
`fly unpause-pipeline` commands. This allows users to pause or unpause every
pipeline on a team at the same time. #4092

#### <sub><sup><a name="5133" href="#5133">:link:</a></sup></sub> fix

* In the case that a user has multiple roles on a team, the pills on the team headers on the dashboard now accurately reflect the logged-in user's most-privileged role on each team. #5133

#### <sub><sup><a name="5118" href="#5118">:link:</a></sup></sub> feature

* Improved the performance of the dashboard by only rendering the pipeline cards that are visible. #5118

#### <sub><sup><a name="4847" href="#4847">:link:</a></sup></sub> fix

* Set a default value of `4h` for `rebalance-interval`. Previously, this value was unset. With the new default, the workers will reconnect to a randomly selected TSA (SSH Gateway) every 4h.

#### <sub><sup><a name="5015" href="#5015">:link:</a></sup></sub> fix

* With #5015, worker state metrics will be emitted even for states with 0 workers, rather than not emitting the metric at all. This should make it easier to confirm that there are in fact 0 stalled workers as opposed to not having any knowledge of it.
