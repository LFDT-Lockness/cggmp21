#!/usr/bin/env bash

m_branch=m;
changelog_file=CHANGELOG.md;

# fetch master since we might be in a shallow clone
git fetch origin "$m_branch:$m_branch" --depth=1

changed=0;
for log in "$changelog_file" */"$changelog_file"; do
    dir=$(dirname "$log");
    # check if version changed
    if git diff "$m_branch" -- "$dir/Cargo.toml" | grep -q "^-version = "; then
        # check if changelog updated
        if git diff --exit-code --no-patch "$m_branch" -- "$log"; then
            echo "$dir version changed, but $log is not updated"
            changed=1;
        fi
    fi
done

exit "$changed";
