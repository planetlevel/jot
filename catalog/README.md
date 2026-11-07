# The JOT catalog

The catalog is the sensors, rules and reports that come with JOT. The Assistant searches it for what fits an application and proposes copies, which you apply to the project's own `.jot/jot.yaml`, where they can be changed. Nothing is loaded from the catalog while an application runs.

## How it is organized

An area is a concern, like SQL, cryptography or known vulnerabilities. An area is one file, like `sql.jot`, or a folder of files when there are many, like `cve/`. The files are the same format as any `.jot` file, with `sensors:` and `reports:` lists.
A rule is a sensor with `block-when`, and it is copied with `protect: false` so it only reports until you turn it on.

The first lines of an area's file are comments that say what it is, and the first sentence is how the Assistant describes it to a person. A folder says the same in its `README.md`.

    # JOT catalog, sql
    # SQL. The connections opened, the statements run, what they changed and what came back.

## How it is found

The Assistant lists the areas, then looks inside the ones that fit, and it can search by words. A search matches the name, description, methods and scopes of an item, and the comment above it. That comment is where a CVE rule says its library and vulnerable versions, so searching a library's name finds the rules that may apply to it.
A report names the sensors it reads, and the Assistant adds those sensors with it.

## Adding to it

Add a sensor to the area it belongs in, or start a new area with a new file. Name it with lower case words joined by `-`, domain first, like `sql-statement`. Start the description with "Identifies", and capture only what is safe to record. Reports read only fields that a sensor captures.
The catalog tests check every item the same way the dashboard does, so a mistake fails the build. Run them with `python3 dashboard/tests/test_dashboard.py CatalogTests`.

The CVE rules in `cve/` are made by `tools/vulnpoint2jot.py`, see the README in that folder.
