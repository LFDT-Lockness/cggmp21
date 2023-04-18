Core key share is obtained as an output of [key generation protocol](crate::keygen()).
It can not be used in signing protocol as it lacks of required auxiliary information.
You need to carry out [key refresh protocol](crate::key_refresh()) to obtain "completed"
[KeyShare].
