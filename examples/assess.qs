# assess.qs — a runnable example of the shared QYVORA scripting engine driving
# imhotep's offline cloud analysis pipeline.
#
#     imhotep script run examples/assess.qs
#
# imhotep is offline and deterministic, so this needs no target setup: with no
# snapshot configured the binding runs the built-in simulation.

# Select the deterministic simulation (the default when no target is set).
set assess.sim -> "true"

# Run the full analysis pipeline. Capability ids such as "cloud.iam" name an
# analysis domain; running one runs the pipeline that covers it.
run assess

# Read live properties from the completed run via $(...).
echo -> "target   = $(target.name)"
echo -> "assets   = $(result.assets)"
echo -> "findings = $(result.findings)"
echo -> "score    = $(result.score) ($(result.level))"

# Show capability metadata and write a Markdown report artifact.
show cloud.iam
report -> "imhotep-report"

echo -> "done"
