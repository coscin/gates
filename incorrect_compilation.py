# I have a suspicion this policy is being compiled incorrectly.
import sys
sys.path.append('../frenetic/lang/python')
import frenetic
from frenetic.syntax import *

app = frenetic.App()
brdcast = "ff:ff:ff:ff:ff:ff"
pred1 = Test(Switch(1)) & Test(Location(Physical(2)))
pred2 = Test(Switch(1)) & Test(Location(Physical(2))) & Test(EthDst(brdcast))
pred3 = Test(Switch(1)) & Test(Location(Physical(1))) & Test(EthDst(brdcast))
send_to_controller = Mod(Location(Pipe("learning_switch_app")))
# bad_policy = pred1.ite(send_to_controller,
#   pred2.ite(Mod(Location(Physical(1))),
#     Filter(pred3) >> Mod(Location(Physical(2))))
# )
bad_policy = pred1.ite(send_to_controller, Filter(pred3) >> Mod(Location(Physical(2)))) 
app.update(bad_policy)
app.start_event_loop()
