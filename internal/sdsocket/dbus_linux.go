package sdsocket

import (
	"context"
	"fmt"

	"github.com/godbus/dbus/v5"
)

const (
	systemdDest   = "org.freedesktop.systemd1"
	systemdPath   = dbus.ObjectPath("/org/freedesktop/systemd1")
	managerIface  = "org.freedesktop.systemd1.Manager"
	unitIface     = "org.freedesktop.systemd1.Unit"
	socketIface   = "org.freedesktop.systemd1.Socket"
	propertyGet   = "org.freedesktop.DBus.Properties.Get"
	listByPattern = managerIface + ".ListUnitsByPatterns"
)

// listedUnit is the a(ssssssouso) row of ListUnitsByPatterns.
type listedUnit struct {
	Name, Description, Load, Active, Sub, Following string
	Path                                            dbus.ObjectPath
	JobID                                           uint32
	JobType                                         string
	JobPath                                         dbus.ObjectPath
}

type dbusLister struct{}

// NewDBusLister lists socket units over the system bus. Unprivileged reads are allowed
// by systemd's bus policy.
func NewDBusLister() Lister { return dbusLister{} }

func (dbusLister) SocketUnits(ctx context.Context) ([]Unit, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("connect system bus: %w", err)
	}
	defer conn.Close()

	var listed []listedUnit
	manager := conn.Object(systemdDest, systemdPath)
	if err := manager.CallWithContext(ctx, listByPattern, 0, []string{"active"}, []string{"*.socket"}).Store(&listed); err != nil {
		return nil, fmt.Errorf("list socket units: %w", err)
	}

	units := make([]Unit, 0, len(listed))
	for _, l := range listed {
		obj := conn.Object(systemdDest, l.Path)
		var listens []Listen
		if err := getProperty(ctx, obj, socketIface, "Listen", &listens); err != nil {
			return nil, fmt.Errorf("%s Listen: %w", l.Name, err)
		}
		var triggers []string
		if err := getProperty(ctx, obj, unitIface, "Triggers", &triggers); err != nil {
			return nil, fmt.Errorf("%s Triggers: %w", l.Name, err)
		}
		u := Unit{Name: l.Name, Listens: listens}
		if len(triggers) > 0 {
			u.Service = triggers[0]
		}
		units = append(units, u)
	}
	return units, nil
}

// getProperty reads one property with a context, which BusObject.GetProperty lacks.
func getProperty(ctx context.Context, obj dbus.BusObject, iface, name string, out any) error {
	var v dbus.Variant
	if err := obj.CallWithContext(ctx, propertyGet, 0, iface, name).Store(&v); err != nil {
		return err
	}
	return v.Store(out)
}
