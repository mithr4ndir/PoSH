#Find groups with managedby filled out and description with Approv on description
get-adgroup -filter {description -like "Approv*"} -pro description,managedby | where {$_.managedby -notlike $null} | measure

