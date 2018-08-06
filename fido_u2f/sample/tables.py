from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import relationship

from ..enums import U2FTransport
from ..device import DeviceRegistration


db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'User'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    devices = relationship('Device', back_populates='user')

    def __init__(self, name=None):
        self.name = name

    def __repr__(self):
       return "<User(%s, name='%s')>" % (self.id, self.name)


class Device(db.Model, DeviceRegistration):
    __tablename__ = 'Device'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('User.id'))
    user = relationship("User", back_populates="devices")

    """The U2F protocol version to use."""
    version = Column(String)
    """The appId used during registration."""
    app_id = Column(String)
    """The raw `keyHandle`."""
    key_handle = Column(LargeBinary)
    """The raw `pubKey`."""
    public_key = Column(LargeBinary)
    """An integer-encoded `U2FTransport`. Use `u2f_transports` instead."""
    transports = Column(Integer)
    """A 32-bit unsigned integer representing the last seen counter."""
    counter = Column(Integer)

    @property
    def u2f_transports(self):
        if self.transports < 0:
            return None
        return U2FTransport._from_internal_int(self.transports)

    @u2f_transports.setter
    def u2f_transports(
        self,
        transports,
    ):
        self.transports = U2FTransport._to_internal_int(transports)
