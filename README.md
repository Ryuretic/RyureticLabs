# Ryuretic Labs

Ryuretic draws its inspiration from Pyretic, which already offers powerful, modular abstractions for network operators; however, Ryuretic also builds on Ryu's greater variety of packet match fields and its access to advanced OpenFlow protocols. This framework allows programmers to create new, extensible, and more powerful network applications at a much higher level of abstraction. As Pyretic does with POX, Ryuretic places an additional abstraction layer over the Ryu framework for network application development. Additionally, its abstractions allow researchers to target specific layers of the OSI model and install both proactive and reactive rule sets, without immersing themselves in the Ryu architecture.

The modularity of Ryuretic also means that programmers
can easily create target-specific programs (e.g., load balancing,
security, traffic engineering, etc.) separately, and then integrate
these features into their switches via the Ryuretic coupler.
Researchers can also customize their security features to
operate at specific layers of the OSI model and produce more
specialized applications. Meanwhile, network operators benefit
from an ability to choose and implement the network modules
most applicable for their network’s requirements.
As mentioned previously, Ryuretic offers users the ability to
proactively and reactively interact with packets. With proactive
measures, Ryuretic does not wait for a packet to arrive.
Instead, flow rules consisting of user provided match and
operation specifications are immediately passed to switches at
startup. Currently, Ryuretic proactively supports forwarding,
dropping and redirecting matched packets.

When a packet arrives (i.e., a packet event occurs),
Ryuretic first parses the packet and creates a packet object
(pkt). This new object, contains a timestamp,
packet inport, datapath (e.g., switch ID), and packet
header fields. Once pkt is built, it is passed to its corresponding
handler as determined by its place in the OSI model (i.e., L2,
L3, L4, or Shim Layer). This allows programmers to better
target specific protocols in their applications. Consequently,
each pkt object also contains the header information from
the lower layers (i.e., if a TCP pkt is built, then it will also
contain metadata for IP and Ethernet). Within each handler,
the network operator calls network applications to return the
hashes (fields and ops) and then passes them to match and
actions objects required for the Ryu platform. So, when a
module is created, the user can choose to return specific
match fields (fields) and their operation parameters (ops). Both
contain keys that map to specific fields in each object. The keys
for fields are shown in Table IV while the keys for ops are
summarized in Table III. When a user creates a new module,
only the keys that hash to specific matching packet header
fields need be set in the fields object. Similarly, operation
requirements (e.g., idle timeout, hard timeout, priority, action,
and new port) are specified in ops.
When fields and ops are returned to the coupler, it creates


Labs are located [here](https://github.com/Ryuretic/RyureticLabs/wiki/Lab-1:-Rogue-NAT-Detector).
