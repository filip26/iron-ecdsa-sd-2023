package com.apicatalog.rdf.canon;

import java.util.Comparator;

import com.apicatalog.rdf.RdfNQuad;

public class RdfNQuadComparator implements Comparator<RdfNQuad> {

    protected final boolean asc;

    protected static Comparator<RdfNQuad> ASC = new RdfNQuadComparator(true);
    protected static Comparator<RdfNQuad> DESC = new RdfNQuadComparator(false);

    public static Comparator<RdfNQuad> asc() {
        return ASC;
    }

    public static Comparator<RdfNQuad> desc() {
        return DESC;
    }

    protected RdfNQuadComparator(boolean asc) {
        this.asc = asc;
    }

    @Override
    public int compare(RdfNQuad o1, RdfNQuad o2) {
        return (asc ? 1 : -1) * o1.toString().compareTo(o2.toString());
    }
}
