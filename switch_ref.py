# switch_ref.py
# Helper class to store switch information.  Stolen from examples, but useful...

class SwitchRef(object):
  def __init__(self, id, ports):
    self.id = id
    self.ports = ports

  def __eq__(self, other):
    return (isinstance(other, self.__class__) and self.id == other.id)

  def __hash__(self):
    return self.id.__hash__()
