﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.Contracts;
using System.Runtime.InteropServices;
using Meadow.Units.Conversions;

namespace Meadow.Units
{
    /// <summary>
    /// Represents Frequency
    /// </summary>
    [Serializable]
    [ImmutableObject(true)]
    [StructLayout(LayoutKind.Sequential)]
    public struct Frequency :
        IUnitType, IComparable, IFormattable, IConvertible,
        IEquatable<double>, IComparable<double>
    {
        /// <summary>
        /// Creates a new `Frequency` object.
        /// </summary>
        /// <param name="value">The Frequency value.</param>
        /// <param name="type">kilometers meters per second by default.</param>
        public Frequency(double value, UnitType type = UnitType.Hertz)
        {
            //always store reference value
            Unit = type;
            Value = FrequencyConversions.Convert(value, type, UnitType.Hertz);
        }

        public Frequency(Frequency frequency)
        {
            this.Value = frequency.Value;
            this.Unit = frequency.Unit;
        }

        /// <summary>
        /// Internal canonical value.
        /// </summary>
        private readonly double Value;

        /// <summary>
        /// The unit that describes the value.
        /// </summary>
        public UnitType Unit { get; set; }

        /// <summary>
        /// The type of units available to describe the Frequency.
        /// </summary>
        public enum UnitType
        {
            Gigahertz,
            Megahertz,
            Kilohertz,
            Hertz,
        }

        public double Gigahertz => From(UnitType.Gigahertz);
        public double Megahertz => From(UnitType.Megahertz);
        public double Kilohertz => From(UnitType.Kilohertz);
        public double Hertz => From(UnitType.Hertz);

        [Pure]
        public double From(UnitType convertTo)
        {
            return FrequencyConversions.Convert(Value, UnitType.Hertz, convertTo);
        }

        [Pure]
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) { return false; }
            if (Equals(this, obj)) { return true; }
            return obj.GetType() == GetType() && Equals((Frequency)obj);
        }

        [Pure] public override int GetHashCode() => Value.GetHashCode();

        // implicit conversions
        [Pure] public static implicit operator Frequency(ushort value) => new Frequency(value);
        [Pure] public static implicit operator Frequency(short value) => new Frequency(value);
        [Pure] public static implicit operator Frequency(uint value) => new Frequency(value);
        [Pure] public static implicit operator Frequency(long value) => new Frequency(value);
        [Pure] public static implicit operator Frequency(int value) => new Frequency(value);
        [Pure] public static implicit operator Frequency(float value) => new Frequency(value);
        [Pure] public static implicit operator Frequency(double value) => new Frequency(value);
        [Pure] public static implicit operator Frequency(decimal value) => new Frequency((double)value);

        // Comparison
        [Pure] public bool Equals(Frequency other) => Value == other.Value;
        [Pure] public static bool operator ==(Frequency left, Frequency right) => Equals(left.Value, right.Value);
        [Pure] public static bool operator !=(Frequency left, Frequency right) => !Equals(left.Value, right.Value);
        [Pure] public int CompareTo(Frequency other) => Equals(this.Value, other.Value) ? 0 : this.Value.CompareTo(other.Value);
        [Pure] public static bool operator <(Frequency left, Frequency right) => Comparer<double>.Default.Compare(left.Value, right.Value) < 0;
        [Pure] public static bool operator >(Frequency left, Frequency right) => Comparer<double>.Default.Compare(left.Value, right.Value) > 0;
        [Pure] public static bool operator <=(Frequency left, Frequency right) => Comparer<double>.Default.Compare(left.Value, right.Value) <= 0;
        [Pure] public static bool operator >=(Frequency left, Frequency right) => Comparer<double>.Default.Compare(left.Value, right.Value) >= 0;

        // Math
        [Pure] public static Frequency operator +(Frequency lvalue, Frequency rvalue) => new Frequency(lvalue.Value + rvalue.Value);
        [Pure] public static Frequency operator -(Frequency lvalue, Frequency rvalue) => new Frequency(lvalue.Value - rvalue.Value);
        [Pure] public static Frequency operator /(Frequency lvalue, Frequency rvalue) => new Frequency(lvalue.Value / rvalue.Value);
        [Pure] public static Frequency operator *(Frequency lvalue, Frequency rvalue) => new Frequency(lvalue.Value * rvalue.Value);
        /// <summary>
        /// Returns the absolute length, that is, the length without regards to
        /// negative polarity
        /// </summary>
        /// <returns></returns>
        [Pure] public Frequency Abs() { return new Frequency(Math.Abs(this.Value)); }

        // ToString()
        [Pure] public override string ToString() => Value.ToString();
        [Pure] public string ToString(string format, IFormatProvider formatProvider) => Value.ToString(format, formatProvider);

        // IComparable
        [Pure] public int CompareTo(object obj) => Value.CompareTo(obj);
        [Pure] public TypeCode GetTypeCode() => Value.GetTypeCode();
        [Pure] public bool ToBoolean(IFormatProvider provider) => ((IConvertible)Value).ToBoolean(provider);
        [Pure] public byte ToByte(IFormatProvider provider) => ((IConvertible)Value).ToByte(provider);
        [Pure] public char ToChar(IFormatProvider provider) => ((IConvertible)Value).ToChar(provider);
        [Pure] public DateTime ToDateTime(IFormatProvider provider) => ((IConvertible)Value).ToDateTime(provider);
        [Pure] public decimal ToDecimal(IFormatProvider provider) => ((IConvertible)Value).ToDecimal(provider);
        [Pure] public double ToDouble(IFormatProvider provider) => Value;
        [Pure] public short ToInt16(IFormatProvider provider) => ((IConvertible)Value).ToInt16(provider);
        [Pure] public int ToInt32(IFormatProvider provider) => ((IConvertible)Value).ToInt32(provider);
        [Pure] public long ToInt64(IFormatProvider provider) => ((IConvertible)Value).ToInt64(provider);
        [Pure] public sbyte ToSByte(IFormatProvider provider) => ((IConvertible)Value).ToSByte(provider);
        [Pure] public float ToSingle(IFormatProvider provider) => ((IConvertible)Value).ToSingle(provider);
        [Pure] public string ToString(IFormatProvider provider) => Value.ToString(provider);
        [Pure] public object ToType(Type conversionType, IFormatProvider provider) => ((IConvertible)Value).ToType(conversionType, provider);
        [Pure] public ushort ToUInt16(IFormatProvider provider) => ((IConvertible)Value).ToUInt16(provider);
        [Pure] public uint ToUInt32(IFormatProvider provider) => ((IConvertible)Value).ToUInt32(provider);
        [Pure] public ulong ToUInt64(IFormatProvider provider) => ((IConvertible)Value).ToUInt64(provider);

        [Pure]
        public int CompareTo(double? other)
        {
            return (other is null) ? -1 : (Value).CompareTo(other.Value);
        }

        [Pure] public bool Equals(double? other) => Value.Equals(other);
        [Pure] public bool Equals(double other) => Value.Equals(other);
        [Pure] public int CompareTo(double other) => Value.CompareTo(other);
    }
}