# Social_Media_App
tst
1. Creating a New Branch
When you start a new feature or work on a separate part of the project, create a new branch. This keeps your work organized and isolated from the main codebase.

bash
git branch <branch-name>       # Create a new branch
git checkout <branch-name>     # Switch to the new branch
Alternative: You can create and switch to a branch in one command:
bash
git checkout -b <branch-name>
2. Making Changes and Checking Status
After switching to the new branch, make changes to your files. Once you’re ready, check the status to see which files have been modified:

bash

git status
This command shows modified, added, or deleted files since the last commit.
3. Staging Changes
To prepare your changes for a commit, you need to stage them. This adds the files to the staging area.

bash

git add <file>             # Stage a specific file
git add .                  # Stage all changes in the current directory
Staging allows you to choose which changes to include in the next commit.
4. Committing Changes
Now, commit your staged changes with a meaningful message that describes what you did. This message will help others (and future you!) understand the changes.

bash

git commit -m "Add a brief description of the changes"
Good commit messages are concise but descriptive (e.g., "Add search functionality to homepage").
5. Working with Multiple Commits on a Branch
As you continue working, you can make and commit multiple changes. Each commit represents a snapshot of your project at a certain point in time.

bash

git add .                   # Stage changes
git commit -m "Another update or fix"
6. Viewing Commit History
To see the history of commits on your branch, use:

bash

git log
This shows each commit with its unique hash, author, date, and message.
7. Switching Branches
You can switch between branches anytime:

bash

git checkout <branch-name>
Note: If you have uncommitted changes, you’ll need to either commit, stash, or discard them before switching.
8. Merging Branches
Once you’ve completed work on your feature branch, you can merge it back into the main branch (often main or master).

bash

git checkout main                 # Switch to the main branch
git merge <branch-name>           # Merge the feature branch into main
9. Pushing Your Branch and Commits to Remote
To share your branch and commits with others, push them to the remote repository.

bash

git push origin <branch-name>
This sends your branch and its commits to the remote server, where others can view and collaborate.
10. Deleting the Branch (Optional)
Once the branch has been merged and is no longer needed, you can delete it:

bash

git branch -d <branch-name>         # Delete a local branch
git push origin --delete <branch-name>  # Delete the branch on the remote
By building branches, committing changes incrementally, and merging only when features are complete, you keep your codebase organized and collaborative-friendly. Let me know if you need further help!